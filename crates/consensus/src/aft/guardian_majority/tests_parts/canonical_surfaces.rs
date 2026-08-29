#[test]
fn reset_promotes_unique_quorum_candidate_for_committed_height() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let block_hash = [9u8; 32];
    let validators = AuthenticatedValidators::new(4);
    validators.install(&mut engine, 5);
    engine.vote_pool.insert(
        5,
        HashMap::from([(
            block_hash,
            vec![
                validators.signed_vote(0, 5, 0, block_hash),
                validators.signed_vote(1, 5, 0, block_hash),
                validators.signed_vote(2, 5, 0, block_hash),
            ],
        )]),
    );

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, block_hash);
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .len(),
            1
        );
}

#[test]
fn reset_does_not_promote_quorum_candidate_whose_votes_do_not_verify() {
    // The promotion path assembles a certificate from the local pool and then
    // propagates it. Forged votes must not survive that assembly even though
    // they are numerous enough to clear the threshold.
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let block_hash = [29u8; 32];
    let validators = AuthenticatedValidators::new(4);
    validators.install(&mut engine, 5);
    let forged = |index: usize| {
        let mut vote = validators.signed_vote(index, 5, 0, block_hash);
        vote.signature = vec![0xAAu8; 64];
        vote
    };
    engine.vote_pool.insert(
        5,
        HashMap::from([(block_hash, vec![forged(0), forged(1), forged(2)])]),
    );

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert!(engine.highest_qc.height < 5);
    assert!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .is_empty()
        );
}

#[test]
fn asymptote_reset_does_not_promote_vote_only_quorum_candidate_for_committed_height() {
    // The votes here are genuine, so this isolates the Asymptote collapse
    // requirement. With forged votes the assertion would hold for the wrong
    // reason and would stop proving anything about collapse backing.
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let block_hash = [19u8; 32];
    let validators = AuthenticatedValidators::new(4);
    validators.install(&mut engine, 5);
    engine.vote_pool.insert(
        5,
        HashMap::from([(
            block_hash,
            vec![
                validators.signed_vote(0, 5, 0, block_hash),
                validators.signed_vote(1, 5, 0, block_hash),
                validators.signed_vote(2, 5, 0, block_hash),
            ],
        )]),
    );

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert!(engine.highest_qc.height < 5);
    assert!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .is_empty()
        );
}

#[test]
fn reset_promotes_recovered_header_for_committed_height() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x45u8; 32],
        parent_block_commitment_hash: [0x34u8; 32],
        transactions_root_hash: [0x23u8; 32],
        resulting_state_root_hash: [0x13u8; 32],
        previous_canonical_collapse_commitment_hash: [0x12u8; 32],
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &recovered_header,
    ));

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.view, recovered_header.view);
    assert_eq!(
        engine.highest_qc.block_hash,
        recovered_header.canonical_block_commitment_hash
    );
}

#[test]
fn synthetic_parent_qc_uses_recovered_header_hint() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 4,
        view: 7,
        canonical_block_commitment_hash: [0x56u8; 32],
        parent_block_commitment_hash: [0x46u8; 32],
        transactions_root_hash: [0x36u8; 32],
        resulting_state_root_hash: [0x26u8; 32],
        previous_canonical_collapse_commitment_hash: [0x26u8; 32],
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &recovered_header,
    ));

    let parent_qc = engine
        .synthetic_parent_qc_for_height(5)
        .expect("recovered parent QC hint");
    assert_eq!(parent_qc.height, 4);
    assert_eq!(parent_qc.view, recovered_header.view);
    assert_eq!(
        parent_qc.block_hash,
        recovered_header.canonical_block_commitment_hash
    );
}

#[test]
fn recovered_header_for_quorum_certificate_returns_restart_hint() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 6,
        view: 3,
        canonical_block_commitment_hash: [0x66u8; 32],
        parent_block_commitment_hash: [0x56u8; 32],
        transactions_root_hash: [0x46u8; 32],
        resulting_state_root_hash: [0x36u8; 32],
        previous_canonical_collapse_commitment_hash: [0x26u8; 32],
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &recovered_header,
    ));

    let recovered_qc = recovered_header.synthetic_quorum_certificate();
    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_consensus_header_for_quorum_certificate(
            &engine,
            &recovered_qc,
        )
        .expect("matching recovered header hint");
    assert_eq!(resolved, recovered_header);
}

#[test]
fn recovered_certified_header_for_quorum_certificate_returns_restart_entry() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x55u8; 32],
        parent_block_commitment_hash: [0x45u8; 32],
        transactions_root_hash: [0x35u8; 32],
        resulting_state_root_hash: [0x25u8; 32],
        previous_canonical_collapse_commitment_hash: [0x15u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let recovered_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 6,
            view: 3,
            canonical_block_commitment_hash: [0x66u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x46u8; 32],
            resulting_state_root_hash: [0x36u8; 32],
            previous_canonical_collapse_commitment_hash: [0x26u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_certified_header(
        &mut engine,
        &recovered_entry,
    ));

    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_certified_header_for_quorum_certificate(
            &engine,
            &recovered_entry.certified_quorum_certificate(),
        )
        .expect("matching recovered certified header hint");
    assert_eq!(resolved, recovered_entry);
}

#[test]
fn observe_recovered_certified_header_rejects_conflicting_parent_state_root() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 7,
        view: 4,
        canonical_block_commitment_hash: [0x77u8; 32],
        parent_block_commitment_hash: [0x67u8; 32],
        transactions_root_hash: [0x57u8; 32],
        resulting_state_root_hash: [0x47u8; 32],
        previous_canonical_collapse_commitment_hash: [0x37u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let conflicting_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 8,
            view: 5,
            canonical_block_commitment_hash: [0x88u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x68u8; 32],
            resulting_state_root_hash: [0x58u8; 32],
            previous_canonical_collapse_commitment_hash: [0x48u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: [0xffu8; 32],
    };

    assert!(!<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_certified_header(
        &mut engine,
        &conflicting_entry,
    ));
}

#[test]
fn header_for_quorum_certificate_returns_recovered_restart_header() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 6,
        view: 2,
        canonical_block_commitment_hash: [0x61u8; 32],
        parent_block_commitment_hash: [0x51u8; 32],
        transactions_root_hash: [0x41u8; 32],
        resulting_state_root_hash: [0x31u8; 32],
        previous_canonical_collapse_commitment_hash: [0x21u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 7,
            view: 3,
            canonical_block_commitment_hash: [0x71u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x51u8; 32],
            resulting_state_root_hash: [0x41u8; 32],
            previous_canonical_collapse_commitment_hash: [0x31u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };
    let payload = RecoverableSlotPayloadV5 {
        height: 7,
        view: 3,
        producer_account_id: AccountId([0x72u8; 32]),
        block_commitment_hash: certified_entry.header.canonical_block_commitment_hash,
        parent_block_hash: certified_entry.header.parent_block_commitment_hash,
        canonical_order_certificate: CanonicalOrderCertificate {
            height: 7,
            bulletin_commitment: BulletinCommitment {
                height: 7,
                cutoff_timestamp_ms: 1_760_000_777_000,
                bulletin_root: [0x73u8; 32],
                entry_count: 0,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 7,
                bulletin_commitment_hash: [0x74u8; 32],
                recoverability_root: [0x75u8; 32],
            },
            randomness_beacon: [0x76u8; 32],
            ordered_transactions_root_hash: certified_entry.header.transactions_root_hash,
            resulting_state_root_hash: certified_entry.header.resulting_state_root_hash,
            proof: CanonicalOrderProof::default(),
            omission_proofs: Vec::new(),
            boundary_tx_hashes: Vec::new(),
            boundary_omission_justifications: Vec::new(),
        },
        ordered_transaction_bytes: Vec::new(),
        canonical_order_publication_bundle_bytes: Vec::new(),
        canonical_bulletin_close_bytes: Vec::new(),
        canonical_bulletin_availability_certificate_bytes: Vec::new(),
        bulletin_surface_entries: Vec::new(),
    };
    let restart_entry =
        recovered_restart_block_header_entry(&payload, &certified_entry).expect("restart entry");

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_restart_block_header(
        &mut engine,
        &restart_entry,
    ));

    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &restart_entry.certified_quorum_certificate(),
        )
        .expect("matching recovered restart header");
    assert_eq!(resolved, restart_entry.header);
}

#[test]
fn observe_recovered_restart_block_header_rejects_conflicting_parent_qc() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 8,
        view: 4,
        canonical_block_commitment_hash: [0x81u8; 32],
        parent_block_commitment_hash: [0x71u8; 32],
        transactions_root_hash: [0x61u8; 32],
        resulting_state_root_hash: [0x51u8; 32],
        previous_canonical_collapse_commitment_hash: [0x41u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 9,
            view: 5,
            canonical_block_commitment_hash: [0x91u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x71u8; 32],
            resulting_state_root_hash: [0x61u8; 32],
            previous_canonical_collapse_commitment_hash: [0x51u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };
    let payload = RecoverableSlotPayloadV5 {
        height: 9,
        view: 5,
        producer_account_id: AccountId([0x92u8; 32]),
        block_commitment_hash: certified_entry.header.canonical_block_commitment_hash,
        parent_block_hash: certified_entry.header.parent_block_commitment_hash,
        canonical_order_certificate: CanonicalOrderCertificate {
            height: 9,
            bulletin_commitment: BulletinCommitment {
                height: 9,
                cutoff_timestamp_ms: 1_760_000_999_000,
                bulletin_root: [0x93u8; 32],
                entry_count: 0,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 9,
                bulletin_commitment_hash: [0x94u8; 32],
                recoverability_root: [0x95u8; 32],
            },
            randomness_beacon: [0x96u8; 32],
            ordered_transactions_root_hash: certified_entry.header.transactions_root_hash,
            resulting_state_root_hash: certified_entry.header.resulting_state_root_hash,
            proof: CanonicalOrderProof::default(),
            omission_proofs: Vec::new(),
            boundary_tx_hashes: Vec::new(),
            boundary_omission_justifications: Vec::new(),
        },
        ordered_transaction_bytes: Vec::new(),
        canonical_order_publication_bundle_bytes: Vec::new(),
        canonical_bulletin_close_bytes: Vec::new(),
        canonical_bulletin_availability_certificate_bytes: Vec::new(),
        bulletin_surface_entries: Vec::new(),
    };
    let mut restart_entry =
        recovered_restart_block_header_entry(&payload, &certified_entry).expect("restart entry");
    restart_entry.header.parent_qc.block_hash[0] ^= 0xFF;

    assert!(!<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_restart_block_header(
        &mut engine,
        &restart_entry,
    ));
}

#[test]
fn aft_recovered_trait_paths_match_legacy_wrappers() {
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x51u8; 32],
        parent_block_commitment_hash: [0x41u8; 32],
        transactions_root_hash: [0x31u8; 32],
        resulting_state_root_hash: [0x21u8; 32],
        previous_canonical_collapse_commitment_hash: [0x11u8; 32],
    };
    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 6,
            view: 3,
            canonical_block_commitment_hash: [0x61u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x41u8; 32],
            resulting_state_root_hash: [0x31u8; 32],
            previous_canonical_collapse_commitment_hash: [0x21u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };
    let restart_entry = sample_recovered_restart_entry(
        &certified_entry.header,
        certified_entry.certified_quorum_certificate(),
        certified_entry.header.resulting_state_root_hash,
        7,
        4,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
    );

    let mut legacy_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let mut aft_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut legacy_engine,
        &previous_header,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_certified_header(
        &mut legacy_engine,
        &certified_entry,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_restart_block_header(
        &mut legacy_engine,
        &restart_entry,
    ));

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_consensus_header(
        &mut aft_engine,
        &previous_header,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_certified_header(
        &mut aft_engine,
        &certified_entry,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_restart_header(
        &mut aft_engine,
        &restart_entry,
    ));

    assert_eq!(
        legacy_engine.recovered_headers,
        aft_engine.recovered_headers
    );
    assert_eq!(
        legacy_engine.recovered_certified_headers,
        aft_engine.recovered_certified_headers
    );
    assert_eq!(
        legacy_engine.recovered_restart_headers,
        aft_engine.recovered_restart_headers
    );

    let recovered_qc = previous_header.synthetic_quorum_certificate();
    let certified_qc = certified_entry.certified_quorum_certificate();
    let restart_qc = restart_entry.certified_quorum_certificate();
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_consensus_header_for_quorum_certificate(
                &legacy_engine,
                &recovered_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &aft_engine,
                &recovered_qc,
            )
        );
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_certified_header_for_quorum_certificate(
                &legacy_engine,
                &certified_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &aft_engine,
                &certified_qc,
            )
        );
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                &legacy_engine,
                &restart_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &aft_engine,
                &restart_qc,
            )
        );
}

#[test]
fn observe_aft_recovered_state_surface_matches_manual_header_seeding() {
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x51u8; 32],
        parent_block_commitment_hash: [0x41u8; 32],
        transactions_root_hash: [0x31u8; 32],
        resulting_state_root_hash: [0x21u8; 32],
        previous_canonical_collapse_commitment_hash: [0x11u8; 32],
    };
    let certified_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 6,
            view: 3,
            canonical_block_commitment_hash: [0x61u8; 32],
            parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
            transactions_root_hash: [0x41u8; 32],
            resulting_state_root_hash: [0x31u8; 32],
            previous_canonical_collapse_commitment_hash: [0x21u8; 32],
        },
        certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
        certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
    };
    let restart_entry = sample_recovered_restart_entry(
        &certified_entry.header,
        certified_entry.certified_quorum_certificate(),
        certified_entry.header.resulting_state_root_hash,
        7,
        4,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
    );
    let surface = AftRecoveredStateSurface {
        replay_prefix: Vec::new(),
        consensus_headers: vec![previous_header.clone()],
        certified_headers: vec![certified_entry.clone()],
        restart_headers: vec![restart_entry.clone()],
        historical_retrievability: None,
    };

    let mut manual_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let mut surface_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_consensus_header(
        &mut manual_engine,
        &previous_header,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_certified_header(
        &mut manual_engine,
        &certified_entry,
    ));
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_aft_recovered_restart_header(
        &mut manual_engine,
        &restart_entry,
    ));

    let stats = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_state_surface(&mut surface_engine, &surface);

    assert_eq!(stats.accepted_consensus_headers, 1);
    assert_eq!(stats.accepted_certified_headers, 1);
    assert_eq!(stats.accepted_restart_headers, 1);
    assert!(stats.accepted_any());

    assert_eq!(
        manual_engine.recovered_headers,
        surface_engine.recovered_headers
    );
    assert_eq!(
        manual_engine.recovered_certified_headers,
        surface_engine.recovered_certified_headers
    );
    assert_eq!(
        manual_engine.recovered_restart_headers,
        surface_engine.recovered_restart_headers
    );

    let recovered_qc = previous_header.synthetic_quorum_certificate();
    let certified_qc = certified_entry.certified_quorum_certificate();
    let restart_qc = restart_entry.certified_quorum_certificate();
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &manual_engine,
                &recovered_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &surface_engine,
                &recovered_qc,
            )
        );
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &manual_engine,
                &certified_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &surface_engine,
                &certified_qc,
            )
        );
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &manual_engine,
                &restart_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &surface_engine,
                &restart_qc,
            )
        );
}

#[test]
fn recovered_restart_block_header_for_quorum_certificate_returns_later_step_entry() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 10,
        view: 5,
        canonical_block_commitment_hash: [0xA1u8; 32],
        parent_block_commitment_hash: [0x91u8; 32],
        transactions_root_hash: [0x81u8; 32],
        resulting_state_root_hash: [0x71u8; 32],
        previous_canonical_collapse_commitment_hash: [0x61u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let step_one = sample_recovered_restart_entry(
        &previous_header,
        previous_header.synthetic_quorum_certificate(),
        previous_header.resulting_state_root_hash,
        11,
        6,
        0xA2,
        0x82,
        0x72,
        0x62,
        0xB2,
        0xC2,
    );
    let step_two = sample_recovered_restart_entry(
        &step_one.certified_header.header,
        step_one.certified_quorum_certificate(),
        step_one.certified_header.header.resulting_state_root_hash,
        12,
        7,
        0xA3,
        0x83,
        0x73,
        0x63,
        0xB3,
        0xC3,
    );
    let step_three = sample_recovered_restart_entry(
        &step_two.certified_header.header,
        step_two.certified_quorum_certificate(),
        step_two.certified_header.header.resulting_state_root_hash,
        13,
        8,
        0xA4,
        0x84,
        0x74,
        0x64,
        0xB4,
        0xC4,
    );

    for entry in [&step_one, &step_two, &step_three] {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine, entry,
        ));
    }

    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &step_three.certified_quorum_certificate(),
        )
        .expect("later-step recovered restart entry");
    assert_eq!(resolved, step_three);

    let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &step_three.certified_quorum_certificate(),
        )
        .expect("later-step recovered restart header");
    assert_eq!(resolved_header, step_three.header);
}

#[test]
fn recovered_restart_block_header_for_quorum_certificate_returns_fourth_step_entry() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 20,
        view: 9,
        canonical_block_commitment_hash: [0xB1u8; 32],
        parent_block_commitment_hash: [0xA1u8; 32],
        transactions_root_hash: [0x91u8; 32],
        resulting_state_root_hash: [0x81u8; 32],
        previous_canonical_collapse_commitment_hash: [0x71u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let step_one = sample_recovered_restart_entry(
        &previous_header,
        previous_header.synthetic_quorum_certificate(),
        previous_header.resulting_state_root_hash,
        21,
        10,
        0xB2,
        0x92,
        0x82,
        0x72,
        0xC2,
        0xD2,
    );
    let step_two = sample_recovered_restart_entry(
        &step_one.certified_header.header,
        step_one.certified_quorum_certificate(),
        step_one.certified_header.header.resulting_state_root_hash,
        22,
        11,
        0xB3,
        0x93,
        0x83,
        0x73,
        0xC3,
        0xD3,
    );
    let step_three = sample_recovered_restart_entry(
        &step_two.certified_header.header,
        step_two.certified_quorum_certificate(),
        step_two.certified_header.header.resulting_state_root_hash,
        23,
        12,
        0xB4,
        0x94,
        0x84,
        0x74,
        0xC4,
        0xD4,
    );
    let step_four = sample_recovered_restart_entry(
        &step_three.certified_header.header,
        step_three.certified_quorum_certificate(),
        step_three.certified_header.header.resulting_state_root_hash,
        24,
        13,
        0xB5,
        0x95,
        0x85,
        0x75,
        0xC5,
        0xD5,
    );

    for entry in [&step_one, &step_two, &step_three, &step_four] {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine, entry,
        ));
    }

    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &step_four.certified_quorum_certificate(),
        )
        .expect("fourth-step recovered restart entry");
    assert_eq!(resolved, step_four);

    let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &step_four.certified_quorum_certificate(),
        )
        .expect("fourth-step recovered restart header");
    assert_eq!(resolved_header, step_four.header);
}

#[test]
fn recovered_restart_block_header_for_quorum_certificate_returns_fifth_step_entry() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 30,
        view: 14,
        canonical_block_commitment_hash: [0xC1u8; 32],
        parent_block_commitment_hash: [0xB1u8; 32],
        transactions_root_hash: [0xA1u8; 32],
        resulting_state_root_hash: [0x91u8; 32],
        previous_canonical_collapse_commitment_hash: [0x81u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let branch = sample_recovered_restart_entry_branch(&previous_header, 15, 5, 0xD1);
    for entry in &branch {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine, entry,
        ));
    }

    let tail = branch.last().expect("fifth-step branch tail");
    let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &tail.certified_quorum_certificate(),
        )
        .expect("fifth-step recovered restart entry");
    assert_eq!(resolved, *tail);

    let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &tail.certified_quorum_certificate(),
        )
        .expect("fifth-step recovered restart header");
    assert_eq!(resolved_header, tail.header);
}

#[test]
fn retain_recovered_ancestry_ranges_prunes_restart_caches_outside_keep_ranges() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 40,
        view: 19,
        canonical_block_commitment_hash: [0xD1u8; 32],
        parent_block_commitment_hash: [0xC1u8; 32],
        transactions_root_hash: [0xB1u8; 32],
        resulting_state_root_hash: [0xA1u8; 32],
        previous_canonical_collapse_commitment_hash: [0x91u8; 32],
    };
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));

    let branch = sample_recovered_restart_entry_branch(&previous_header, 20, 5, 0xE1);
    for entry in &branch {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine, entry,
        ));
    }

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::retain_recovered_ancestry_ranges(
        &mut engine,
        &[(42, 43), (45, 45)],
    );

    let mut recovered_header_heights = engine.recovered_headers.keys().copied().collect::<Vec<_>>();
    let mut recovered_certified_heights = engine
        .recovered_certified_headers
        .keys()
        .copied()
        .collect::<Vec<_>>();
    let mut recovered_restart_heights = engine
        .recovered_restart_headers
        .keys()
        .copied()
        .collect::<Vec<_>>();
    recovered_header_heights.sort_unstable();
    recovered_certified_heights.sort_unstable();
    recovered_restart_heights.sort_unstable();

    assert_eq!(recovered_header_heights, vec![42, 43, 45]);
    assert_eq!(recovered_certified_heights, vec![42, 43, 45]);
    assert_eq!(recovered_restart_heights, vec![42, 43, 45]);
}

#[test]
fn observe_recovered_consensus_header_rejects_conflicting_parent_link() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    let previous_header = RecoveredCanonicalHeaderEntry {
        height: 4,
        view: 1,
        canonical_block_commitment_hash: [0x61u8; 32],
        parent_block_commitment_hash: [0x51u8; 32],
        transactions_root_hash: [0x41u8; 32],
        resulting_state_root_hash: [0x31u8; 32],
        previous_canonical_collapse_commitment_hash: [0x31u8; 32],
    };
    let conflicting_child = RecoveredCanonicalHeaderEntry {
        height: 5,
        view: 2,
        canonical_block_commitment_hash: [0x62u8; 32],
        parent_block_commitment_hash: [0x99u8; 32],
        transactions_root_hash: [0x42u8; 32],
        resulting_state_root_hash: [0x32u8; 32],
        previous_canonical_collapse_commitment_hash: [0x32u8; 32],
    };

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &previous_header,
    ));
    assert!(!<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_recovered_consensus_header(
        &mut engine,
        &conflicting_child,
    ));
    assert!(!engine.recovered_headers.contains_key(&5));
}

#[test]
fn asymptote_reset_promotes_committed_header_for_committed_height() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let previous_collapse = test_canonical_collapse_object(4, None, [44u8; 32], [45u8; 32]);
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let committed_collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();
    let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
    engine
        .committed_headers
        .insert(committed_header.height, committed_header);
    engine
        .committed_collapses
        .insert(committed_collapse.height, committed_collapse);

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, committed_hash);
    assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .len(),
            1
        );
}

#[test]
fn asymptote_observe_committed_block_ignores_mismatched_collapse_object() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let previous_collapse = test_canonical_collapse_object(4, None, [46u8; 32], [47u8; 32]);
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let mut collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();
    collapse.resulting_state_root_hash[0] ^= 0xFF;

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&collapse),
        );

    assert!(!accepted);
    assert!(!engine
        .committed_headers
        .contains_key(&committed_header.height));

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert!(engine.highest_qc.height < 5);
}

#[test]
fn asymptote_observe_committed_block_with_matching_collapse_enables_reset_promotion() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let collapse_chain = test_canonical_collapse_chain_ending(4, [48u8; 32], [49u8; 32]);
    seed_committed_collapse_chain(&mut engine, &collapse_chain);
    let previous_collapse = collapse_chain.last().unwrap().clone();
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
    let collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&collapse),
        );

    assert!(accepted);
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, committed_hash);
}

#[test]
fn asymptote_reset_replaces_stale_same_height_qc_with_latest_committed_header() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let collapse_chain = test_canonical_collapse_chain_ending(4, [0x51u8; 32], [0x52u8; 32]);
    seed_committed_collapse_chain(&mut engine, &collapse_chain);
    let previous_collapse = collapse_chain.last().unwrap().clone();

    let mut original_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut original_header, &previous_collapse);
    let original_hash = to_root_hash(&original_header.hash().unwrap()).unwrap();
    let original_collapse = derive_canonical_collapse_object_with_previous(
        &original_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();

    let original_accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &original_header,
            Some(&original_collapse),
        );
    assert!(original_accepted);
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);
    assert_eq!(engine.highest_qc.block_hash, original_hash);

    let mut enriched_header = original_header.clone();
    enriched_header.timestamp = enriched_header.timestamp.saturating_add(1);
    enriched_header.timestamp_ms = enriched_header.timestamp_ms.saturating_add(1_000);
    let enriched_hash = to_root_hash(&enriched_header.hash().unwrap()).unwrap();
    assert_ne!(enriched_hash, original_hash);
    let enriched_collapse = derive_canonical_collapse_object_with_previous(
        &enriched_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();
    let enriched_surface = engine
        .canonical_collapse_from_header_surface_with_previous(
            &enriched_header,
            Some(&previous_collapse),
        )
        .expect("enriched header surface should derive");
    assert!(
        canonical_collapse_eq_on_header_surface(&enriched_surface, &enriched_collapse),
        "enriched collapse must match its header surface"
    );
    engine
        .verify_runtime_canonical_collapse_continuity(
            &enriched_collapse,
            Some(&previous_collapse),
        )
        .expect("enriched collapse continuity should verify");
    assert_eq!(
        engine.committed_collapses.get(&previous_collapse.height),
        Some(&previous_collapse)
    );

    let enriched_accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &enriched_header,
            Some(&enriched_collapse),
        );
    assert!(enriched_accepted);
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, enriched_hash);
}

#[test]
fn asymptote_observe_committed_block_accepts_archived_anchor_upgrade() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let collapse_chain = test_canonical_collapse_chain_ending(4, [0x61u8; 32], [0x62u8; 32]);
    seed_committed_collapse_chain(&mut engine, &collapse_chain);
    let previous_collapse = collapse_chain.last().unwrap().clone();
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
    let mut committed_collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut committed_collapse,
        [0x71u8; 32],
        [0x72u8; 32],
        [0x73u8; 32],
    )
    .expect("anchor upgrade");

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&committed_collapse),
        );

    assert!(accepted);
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

    assert_eq!(engine.highest_qc.height, 5);
    assert_eq!(engine.highest_qc.block_hash, committed_hash);
}

#[test]
fn asymptote_observe_committed_block_accepts_header_compatible_materialized_collapse() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let collapse_chain = test_canonical_collapse_chain_ending(4, [0x74u8; 32], [0x75u8; 32]);
    seed_committed_collapse_chain(&mut engine, &collapse_chain);
    let previous_collapse = collapse_chain.last().unwrap().clone();
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    committed_header.canonical_order_certificate = Some(
        build_reference_canonical_order_certificate(&committed_header, &[])
            .expect("reference canonical-order certificate"),
    );
    let committed_collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .expect("materialized collapse");
    let header_surface = engine
        .canonical_collapse_from_header_surface_with_previous(
            &committed_header,
            Some(&previous_collapse),
        )
        .expect("header-surface collapse");
    assert!(
        !canonical_collapse_eq_ignoring_archived_recovered_history_anchor(
            &committed_collapse,
            &header_surface,
        ),
        "full-object equality should differ once ordering materialization is present"
    );
    assert!(
        canonical_collapse_eq_on_header_surface(&committed_collapse, &header_surface),
        "header-surface equality should accept the same committed header"
    );

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&committed_collapse),
        );

    assert!(accepted);
}

#[test]
fn asymptote_observe_committed_block_rejects_succinct_labeled_collapse_until_real_backend() {
    // AFT-CB R4c: SuccinctSp1V1 is a reserved wire variant. Until a real
    // succinct backend lands, the reference runtime rejects any
    // succinct-labeled collapse object outright — even one whose bytes
    // satisfy the zk plugin's simulated recipe.
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let collapse_chain = test_canonical_collapse_chain_ending(4, [0x31u8; 32], [0x32u8; 32]);
    seed_committed_collapse_chain(&mut engine, &collapse_chain);
    let previous_collapse = collapse_chain.last().unwrap().clone();
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let mut committed_collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();
    bind_simulated_succinct_continuity(&mut committed_collapse);

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&committed_collapse),
        );

    assert!(!accepted);
}

#[test]
fn asymptote_observe_committed_block_rejects_corrupted_local_predecessor_chain() {
    // The locally stored predecessor chain is HashPcdV1; corrupting the
    // stored predecessor's proof bytes must reject the committed-block hint.
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let collapse_chain = test_canonical_collapse_chain_ending(4, [0x41u8; 32], [0x42u8; 32]);
    seed_committed_collapse_chain(&mut engine, &collapse_chain);
    let previous_collapse = collapse_chain.last().unwrap().clone();
    let mut stored_previous = previous_collapse.clone();
    stored_previous.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
    engine
        .committed_collapses
        .insert(stored_previous.height, stored_previous);
    let mut committed_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
    let committed_collapse = derive_canonical_collapse_object_with_previous(
        &committed_header,
        &[],
        Some(&previous_collapse),
    )
    .unwrap();

    let accepted =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &committed_header,
            Some(&committed_collapse),
        );

    assert!(!accepted);
}

#[test]
fn asymptote_committed_block_anchor_work_is_bounded_independent_of_retained_height() {
    fn continuity_steps_for_commit_after(previous_height: u64) -> u64 {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let collapse_chain =
            test_canonical_collapse_chain_ending(previous_height, [0x21; 32], [0x22; 32]);
        seed_committed_collapse_chain(&mut engine, &collapse_chain);
        let previous_collapse = collapse_chain.last().unwrap().clone();
        let mut header = build_progress_parent_header(previous_height + 1, 0);
        link_header_to_previous_collapse(&mut header, &previous_collapse);
        let collapse = derive_canonical_collapse_object_with_previous(
            &header,
            &[],
            Some(&previous_collapse),
        )
        .unwrap();

        GuardianMajorityEngine::reset_local_collapse_continuity_steps();
        let accepted =
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
                &mut engine,
                &header,
                Some(&collapse),
            );
        assert!(accepted);
        GuardianMajorityEngine::local_collapse_continuity_steps()
    }

    let shallow = continuity_steps_for_commit_after(4);
    let deep = continuity_steps_for_commit_after(40);
    assert_eq!(shallow, deep, "continuity work grew with retained height");
    assert_eq!(deep, 3, "unexpected steady-state continuity work");
}

#[test]
fn asymptote_bounded_anchor_fails_closed_on_missing_direct_predecessor() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let collapse_chain = test_canonical_collapse_chain_ending(4, [0x23; 32], [0x24; 32]);
    seed_committed_collapse_chain(&mut engine, &collapse_chain);
    let previous_collapse = collapse_chain.last().unwrap().clone();
    engine.committed_collapses.remove(&3);

    let error = engine
        .verify_admitted_canonical_collapse_anchor(&previous_collapse)
        .expect_err("missing direct predecessor must be refused");
    assert!(error.to_string().contains(
        "missing locally committed canonical collapse object for height 3"
    ));

    let mut header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    let collapse =
        derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous_collapse))
            .unwrap();
    assert!(
        !<GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &header,
            Some(&collapse),
        )
    );
    assert!(!engine.committed_collapses.contains_key(&5));
}

#[test]
fn asymptote_bounded_anchor_rejects_altered_recursive_proof_below_predecessor() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let collapse_chain = test_canonical_collapse_chain_ending(4, [0x25; 32], [0x26; 32]);
    seed_committed_collapse_chain(&mut engine, &collapse_chain);
    let previous_collapse = collapse_chain.last().unwrap().clone();
    let mut tampered = collapse_chain[2].clone();
    assert_eq!(tampered.height, 3);
    tampered.continuity_recursive_proof.proof_bytes[0] ^= 0xff;
    engine.committed_collapses.insert(tampered.height, tampered);

    assert!(engine
        .verify_admitted_canonical_collapse_anchor(&previous_collapse)
        .is_err());

    let mut header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    let collapse =
        derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous_collapse))
            .unwrap();
    assert!(
        !<GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &header,
            Some(&collapse),
        )
    );
}

#[test]
fn asymptote_record_rejects_conflicting_readmission_below_successor() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let chain = test_canonical_collapse_chain_ending(4, [0x27; 32], [0x28; 32]);
    seed_committed_collapse_chain(&mut engine, &chain);
    let previous = chain.last().unwrap().clone();

    let mut header_five = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut header_five, &previous);
    let collapse_five =
        derive_canonical_collapse_object_with_previous(&header_five, &[], Some(&previous))
            .unwrap();
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &header_five,
            Some(&collapse_five),
        )
    );

    let mut header_six = build_progress_parent_header(6, 0);
    link_header_to_previous_collapse(&mut header_six, &collapse_five);
    let collapse_six =
        derive_canonical_collapse_object_with_previous(&header_six, &[], Some(&collapse_five))
            .unwrap();
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &header_six,
            Some(&collapse_six),
        )
    );

    let mut forked_header = build_progress_parent_header(5, 1);
    forked_header.state_root = StateRoot(vec![0x5a; 32]);
    link_header_to_previous_collapse(&mut forked_header, &previous);
    let forked =
        derive_canonical_collapse_object_with_previous(&forked_header, &[], Some(&previous))
            .unwrap();
    assert_ne!(
        canonical_collapse_commitment(&forked),
        canonical_collapse_commitment(&collapse_five)
    );
    assert!(
        !<GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &forked_header,
            Some(&forked),
        )
    );
    assert_eq!(engine.committed_collapses.get(&5), Some(&collapse_five));
    assert_eq!(engine.committed_collapses.get(&6), Some(&collapse_six));
}

#[test]
fn asymptote_record_still_readmits_conflicting_unanchored_head() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let chain = test_canonical_collapse_chain_ending(4, [0x2b; 32], [0x2c; 32]);
    seed_committed_collapse_chain(&mut engine, &chain);
    let previous = chain.last().unwrap().clone();

    let mut original_header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut original_header, &previous);
    let original =
        derive_canonical_collapse_object_with_previous(&original_header, &[], Some(&previous))
            .unwrap();
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &original_header,
            Some(&original),
        )
    );

    let mut replacement_header = build_progress_parent_header(5, 1);
    replacement_header.state_root = StateRoot(vec![0x5b; 32]);
    link_header_to_previous_collapse(&mut replacement_header, &previous);
    let replacement =
        derive_canonical_collapse_object_with_previous(&replacement_header, &[], Some(&previous))
            .unwrap();
    assert_ne!(replacement, original);
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
            &mut engine,
            &replacement_header,
            Some(&replacement),
        )
    );
    assert_eq!(engine.committed_collapses.get(&5), Some(&replacement));
}

#[test]
fn full_historical_collapse_verifier_remains_available_for_cold_audit() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let chain = test_canonical_collapse_chain_ending(6, [0x29; 32], [0x2a; 32]);
    seed_committed_collapse_chain(&mut engine, &chain);
    let head = chain.last().unwrap().clone();

    GuardianMajorityEngine::reset_local_collapse_continuity_steps();
    engine
        .verify_local_canonical_collapse_chain(&head)
        .expect("full historical chain verifies");
    assert_eq!(
        GuardianMajorityEngine::local_collapse_continuity_steps(),
        6
    );

    GuardianMajorityEngine::reset_local_collapse_continuity_steps();
    engine
        .verify_admitted_canonical_collapse_anchor(&head)
        .expect("admitted anchor verifies");
    assert_eq!(
        GuardianMajorityEngine::local_collapse_continuity_steps(),
        1
    );

    // A deep payload mutation outside the successor binding is an explicit
    // bounded-anchor nonclaim; the retained full verifier still catches it.
    let mut tampered = chain[1].clone();
    assert_eq!(tampered.height, 2);
    tampered.transactions_root_hash[0] ^= 0xff;
    engine.committed_collapses.insert(tampered.height, tampered);
    assert!(engine
        .verify_local_canonical_collapse_chain(&head)
        .is_err());
    assert!(engine
        .verify_admitted_canonical_collapse_anchor(&head)
        .is_ok());
}

#[tokio::test]
async fn parent_view_anchor_work_is_bounded_independent_of_retained_height() {
    async fn admitted_steps(depth: u64) -> u64 {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let chain = test_canonical_collapse_chain_ending(depth, [0x31; 32], [0x32; 32]);
        seed_committed_collapse_chain(&mut engine, &chain);
        GuardianMajorityEngine::reset_local_collapse_continuity_steps();
        engine
            .verify_canonical_collapse_anchor_with_parent_view(
                chain.last().unwrap(),
                &MockAnchoredView::default(),
            )
            .await
            .unwrap();
        GuardianMajorityEngine::local_collapse_continuity_steps()
    }

    async fn new_head_steps(depth: u64) -> u64 {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let chain = test_canonical_collapse_chain_ending(depth, [0x33; 32], [0x34; 32]);
        seed_committed_collapse_chain(&mut engine, &chain);
        let previous = chain.last().unwrap();
        let mut header = build_progress_parent_header(depth + 1, 0);
        link_header_to_previous_collapse(&mut header, previous);
        let collapse =
            derive_canonical_collapse_object_with_previous(&header, &[], Some(previous)).unwrap();
        GuardianMajorityEngine::reset_local_collapse_continuity_steps();
        engine
            .verify_canonical_collapse_anchor_with_parent_view(
                &collapse,
                &MockAnchoredView::default(),
            )
            .await
            .unwrap();
        GuardianMajorityEngine::local_collapse_continuity_steps()
    }

    assert_eq!(admitted_steps(4).await, admitted_steps(40).await);
    assert_eq!(admitted_steps(40).await, 1);
    assert_eq!(new_head_steps(4).await, new_head_steps(40).await);
    assert_eq!(new_head_steps(40).await, 2);
}

#[tokio::test]
async fn parent_view_anchor_rejects_head_over_a_different_predecessor() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let admitted = test_canonical_collapse_chain_ending(4, [0x35; 32], [0x36; 32]);
    seed_committed_collapse_chain(&mut engine, &admitted);
    let fork = test_canonical_collapse_chain_ending(4, [0x37; 32], [0x38; 32]);
    let fork_previous = fork.last().unwrap();
    let mut header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut header, fork_previous);
    let collapse =
        derive_canonical_collapse_object_with_previous(&header, &[], Some(fork_previous)).unwrap();

    assert!(engine
        .verify_canonical_collapse_anchor_with_parent_view(
            &collapse,
            &MockAnchoredView::default(),
        )
        .await
        .is_err());
}

#[tokio::test]
async fn parent_view_anchor_rejects_mutated_admitted_predecessor_prefix() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let chain = test_canonical_collapse_chain_ending(4, [0x39; 32], [0x3a; 32]);
    seed_committed_collapse_chain(&mut engine, &chain);
    let previous = chain.last().unwrap();
    let mut header = build_progress_parent_header(5, 0);
    link_header_to_previous_collapse(&mut header, previous);
    let collapse =
        derive_canonical_collapse_object_with_previous(&header, &[], Some(previous)).unwrap();
    let mut tampered = chain[2].clone();
    tampered.continuity_recursive_proof.proof_bytes[0] ^= 0xff;
    engine.committed_collapses.insert(tampered.height, tampered);

    assert!(engine
        .verify_canonical_collapse_anchor_with_parent_view(
            &collapse,
            &MockAnchoredView::default(),
        )
        .await
        .is_err());
}

#[tokio::test]
async fn full_parent_view_historical_verifier_remains_for_cold_recovery() {
    let engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let chain = test_canonical_collapse_chain_ending(6, [0x3b; 32], [0x3c; 32]);
    let head = chain.last().unwrap().clone();
    let mut parent_view = MockAnchoredView::default();
    insert_published_collapse_chain(&mut parent_view, &chain);

    GuardianMajorityEngine::reset_local_collapse_continuity_steps();
    engine
        .verify_canonical_collapse_anchor_with_parent_view(&head, &parent_view)
        .await
        .unwrap();
    assert_eq!(
        GuardianMajorityEngine::local_collapse_continuity_steps(),
        6
    );

    let mut tampered = chain[1].clone();
    tampered.transactions_root_hash[0] ^= 0xff;
    parent_view.state.insert(
        aft_canonical_collapse_object_key(tampered.height),
        codec::to_bytes_canonical(&tampered).unwrap(),
    );
    assert!(engine
        .verify_canonical_collapse_anchor_with_parent_view(&head, &parent_view)
        .await
        .is_err());
}
