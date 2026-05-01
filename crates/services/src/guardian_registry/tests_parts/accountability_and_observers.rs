#[test]
fn reporting_aft_omission_auto_accounts_offender_and_stages_next_epoch_eviction() {
    let registry = production_registry();
    let offender = AccountId([11u8; 32]);
    let omission = OmissionProof {
        height: 9,
        offender_account_id: offender,
        tx_hash: [51u8; 32],
        bulletin_root: [52u8; 32],
        details: "candidate order omitted an admitted transaction".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(7, 1), (11, 1), (12, 1)])).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "report_aft_omission@v1",
            &codec::to_bytes_canonical(&omission).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let quarantined: BTreeSet<AccountId> = codec::from_bytes_canonical(
        &state
            .get(QUARANTINED_VALIDATORS_KEY)
            .unwrap()
            .expect("quarantine set stored"),
    )
    .unwrap();
    assert!(quarantined.contains(&offender));

    let stored_sets = read_validator_sets(
        &state
            .get(VALIDATOR_SET_KEY)
            .unwrap()
            .expect("validator sets stored"),
    )
    .unwrap();
    let next = stored_sets.next.expect("next validator set staged");
    assert_eq!(next.effective_from_height, 43);
    assert!(!next
        .validators
        .iter()
        .any(|validator| validator.account_id == offender));

    let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
        &state
            .get(EVIDENCE_REGISTRY_KEY)
            .unwrap()
            .expect("evidence registry stored"),
    )
    .unwrap();
    assert_eq!(evidence_registry.len(), 1);
}

#[test]
fn publishing_aft_canonical_order_artifact_bundle_with_omission_proof_materializes_abort_without_membership_updates(
) {
    let registry = production_registry_without_accountable_membership_updates();
    let base_header = ioi_types::app::BlockHeader {
        height: 10,
        view: 2,
        parent_hash: [11u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_211,
        timestamp_ms: 1_760_000_211_000,
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
    let mut certificate =
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .unwrap();
    let offender = AccountId([44u8; 32]);
    let omission = OmissionProof {
        height: header.height,
        offender_account_id: offender,
        tx_hash: [45u8; 32],
        bulletin_root: certificate.bulletin_commitment.bulletin_root,
        details: "bundle-carried omission remains decisive without membership penalties".into(),
    };
    certificate.omission_proofs = vec![omission.clone()];
    let bundle = canonical_order_publication_bundle_with_retrievability(
        &certificate,
        build_bulletin_surface_entries(header.height, &ordered_transactions).unwrap(),
    );

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(12, 1), (44, 1), (46, 1)])).unwrap(),
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

    let stored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(header.height))
            .unwrap()
            .expect("order abort stored"),
    )
    .unwrap();
    assert_eq!(
        stored_abort.reason,
        CanonicalOrderAbortReason::OmissionDominated
    );
    assert_eq!(
        stored_abort.canonical_order_certificate_hash,
        canonical_order_certificate_hash(&certificate).unwrap()
    );
    assert!(state
        .get(&aft_order_certificate_key(header.height))
        .unwrap()
        .is_none());
    assert!(state
        .get(&aft_bulletin_availability_certificate_key(header.height))
        .unwrap()
        .is_none());
    assert!(state
        .get(&aft_canonical_bulletin_close_key(header.height))
        .unwrap()
        .is_none());
    assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

    let stored_sets = read_validator_sets(
        &state
            .get(VALIDATOR_SET_KEY)
            .unwrap()
            .expect("validator sets stored"),
    )
    .unwrap();
    assert!(stored_sets.next.is_none());
    assert!(stored_sets
        .current
        .validators
        .iter()
        .any(|validator| validator.account_id == offender));

    let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
        &state
            .get(EVIDENCE_REGISTRY_KEY)
            .unwrap()
            .expect("evidence registry stored"),
    )
    .unwrap();
    assert_eq!(evidence_registry.len(), 1);
}

#[test]
fn reporting_aft_omission_remains_published_when_accountable_membership_updates_are_disabled() {
    let registry = production_registry_without_accountable_membership_updates();
    let offender = AccountId([14u8; 32]);
    let omission = OmissionProof {
        height: 10,
        offender_account_id: offender,
        tx_hash: [53u8; 32],
        bulletin_root: [54u8; 32],
        details: "negative ordering object remains decisive without membership penalties".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(7, 1), (14, 1), (15, 1)])).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "report_aft_omission@v1",
            &codec::to_bytes_canonical(&omission).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_omission: OmissionProof = codec::from_bytes_canonical(
        &state
            .get(&aft_omission_proof_key(omission.height, &omission.tx_hash))
            .unwrap()
            .expect("omission proof stored"),
    )
    .unwrap();
    assert_eq!(stored_omission, omission);
    assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

    let stored_sets = read_validator_sets(
        &state
            .get(VALIDATOR_SET_KEY)
            .unwrap()
            .expect("validator sets stored"),
    )
    .unwrap();
    assert!(stored_sets.next.is_none());
    assert!(stored_sets
        .current
        .validators
        .iter()
        .any(|validator| validator.account_id == offender));

    let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
        &state
            .get(EVIDENCE_REGISTRY_KEY)
            .unwrap()
            .expect("evidence registry stored"),
    )
    .unwrap();
    assert_eq!(evidence_registry.len(), 1);
}

#[test]
fn reporting_aft_omission_after_positive_ordering_artifacts_materializes_abort_dominance() {
    let registry = production_registry();
    let base_header = ioi_types::app::BlockHeader {
        height: 18,
        view: 2,
        parent_hash: [31u8; 32],
        parent_state_root: StateRoot(vec![1u8; 32]),
        state_root: StateRoot(vec![2u8; 32]),
        transactions_root: Vec::new(),
        timestamp: 1_760_000_411,
        timestamp_ms: 1_760_000_411_000,
        gas_used: 0,
        validator_set: Vec::new(),
        producer_account_id: AccountId([32u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [33u8; 32],
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
    let tx = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([34u8; 32]),
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
    let ordered_transactions = canonicalize_transactions_for_header(&base_header, &[tx]).unwrap();
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
    let omission = OmissionProof {
        height: header.height,
        offender_account_id: AccountId([35u8; 32]),
        tx_hash: [36u8; 32],
        bulletin_root: certificate.bulletin_commitment.bulletin_root,
        details: "late omission dominates positive ordering artifacts".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(32, 1), (35, 1), (36, 1)])).unwrap(),
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
        run_async(registry.handle_service_call(
            &mut state,
            "report_aft_omission@v1",
            &codec::to_bytes_canonical(&omission).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(header.height))
            .unwrap()
            .expect("order abort stored"),
    )
    .unwrap();
    assert_eq!(
        stored_abort.reason,
        CanonicalOrderAbortReason::OmissionDominated
    );
    assert!(state
        .get(&aft_order_certificate_key(header.height))
        .unwrap()
        .is_none());
    assert!(state
        .get(&aft_bulletin_availability_certificate_key(header.height))
        .unwrap()
        .is_none());
    assert!(state
        .get(&aft_canonical_bulletin_close_key(header.height))
        .unwrap()
        .is_none());
}

#[test]
fn transcript_mismatch_challenge_penalizes_producer_not_observer() {
    let registry = production_registry();
    let producer = AccountId([21u8; 32]);
    let observer = AccountId([22u8; 32]);
    let assignment = AsymptoteObserverAssignment {
        epoch: 7,
        producer_account_id: producer,
        height: 12,
        view: 3,
        round: 0,
        observer_account_id: observer,
    };
    let request = AsymptoteObserverObservationRequest {
        epoch: 7,
        assignment: assignment.clone(),
        block_hash: [61u8; 32],
        guardian_manifest_hash: [62u8; 32],
        guardian_decision_hash: [63u8; 32],
        guardian_counter: 64,
        guardian_trace_hash: [65u8; 32],
        guardian_measurement_root: [66u8; 32],
        guardian_checkpoint_root: [67u8; 32],
    };
    let evidence_hash = canonical_asymptote_observer_observation_request_hash(&request).unwrap();
    let challenge = AsymptoteObserverChallenge {
        challenge_id: [68u8; 32],
        epoch: 7,
        height: 12,
        view: 3,
        kind: AsymptoteObserverChallengeKind::TranscriptMismatch,
        challenger_account_id: observer,
        assignment: Some(assignment),
        observation_request: Some(request),
        transcript: None,
        canonical_close: None,
        evidence_hash,
        details: "observer rejected a malformed canonical observation request".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(21, 1), (22, 1), (23, 1)])).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "report_asymptote_observer_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let quarantined: BTreeSet<AccountId> = codec::from_bytes_canonical(
        &state
            .get(QUARANTINED_VALIDATORS_KEY)
            .unwrap()
            .expect("quarantine set stored"),
    )
    .unwrap();
    assert!(quarantined.contains(&producer));
    assert!(!quarantined.contains(&observer));

    let stored_sets = read_validator_sets(
        &state
            .get(VALIDATOR_SET_KEY)
            .unwrap()
            .expect("validator sets stored"),
    )
    .unwrap();
    let next = stored_sets.next.expect("next validator set staged");
    assert!(!next
        .validators
        .iter()
        .any(|validator| validator.account_id == producer));
    assert!(next
        .validators
        .iter()
        .any(|validator| validator.account_id == observer));
}

#[test]
fn invalid_canonical_close_challenge_blames_producer_and_remains_published_without_quarantine() {
    let registry = production_registry();
    let producer = AccountId([24u8; 32]);
    let observer = AccountId([25u8; 32]);
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: 8,
        height: 13,
        view: 2,
        assignments_hash: [71u8; 32],
        transcripts_root: [72u8; 32],
        challenges_root: [73u8; 32],
        transcript_count: 1,
        challenge_count: 1,
        challenge_cutoff_timestamp_ms: 1_760_000_000,
    };
    let evidence_hash =
        canonical_asymptote_observer_canonical_close_hash(&canonical_close).unwrap();
    let challenge = AsymptoteObserverChallenge {
        challenge_id: [70u8; 32],
        epoch: 8,
        height: 13,
        view: 2,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id: producer,
        assignment: None,
        observation_request: None,
        transcript: None,
        canonical_close: Some(canonical_close.clone()),
        evidence_hash,
        details: "invalid proof-carried canonical close is challenge-dominated".into(),
    };
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(std::slice::from_ref(&challenge))
            .expect("observer challenge root");
    let abort = AsymptoteObserverCanonicalAbort {
        epoch: 8,
        height: 13,
        view: 2,
        assignments_hash: [71u8; 32],
        transcripts_root: [72u8; 32],
        challenges_root,
        transcript_count: 1,
        challenge_count: 1,
        challenge_cutoff_timestamp_ms: canonical_close.challenge_cutoff_timestamp_ms,
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(24, 1), (25, 1)])).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "report_asymptote_observer_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_asymptote_observer_canonical_abort@v1",
            &codec::to_bytes_canonical(&abort).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

    let stored_challenge = state
        .get(&guardian_registry_observer_challenge_key(
            8,
            13,
            2,
            &[70u8; 32],
        ))
        .unwrap()
        .expect("observer challenge stored");
    let restored_challenge: AsymptoteObserverChallenge =
        codec::from_bytes_canonical(&stored_challenge).unwrap();
    assert_eq!(restored_challenge, challenge);

    let stored_abort = state
        .get(&guardian_registry_observer_canonical_abort_key(8, 13, 2))
        .unwrap()
        .expect("canonical abort stored");
    let restored_abort: AsymptoteObserverCanonicalAbort =
        codec::from_bytes_canonical(&stored_abort).unwrap();
    assert_eq!(restored_abort, abort);

    let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
        &state
            .get(EVIDENCE_REGISTRY_KEY)
            .unwrap()
            .expect("evidence registry stored"),
    )
    .unwrap();
    assert_eq!(evidence_registry.len(), 1);

    let stored_sets = read_validator_sets(
        &state
            .get(VALIDATOR_SET_KEY)
            .unwrap()
            .expect("validator sets stored"),
    )
    .unwrap();
    let next = stored_sets.next.expect("next validator set staged");
    assert_eq!(next.validators.len(), 1);
    assert!(!next
        .validators
        .iter()
        .any(|validator| validator.account_id == producer));
    assert!(next
        .validators
        .iter()
        .any(|validator| validator.account_id == observer));
}

#[test]
fn invalid_canonical_close_challenge_remains_published_when_membership_updates_are_disabled() {
    let registry = production_registry_without_accountable_membership_updates();
    let producer = AccountId([26u8; 32]);
    let observer = AccountId([27u8; 32]);
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: 8,
        height: 14,
        view: 1,
        assignments_hash: [76u8; 32],
        transcripts_root: [77u8; 32],
        challenges_root: [78u8; 32],
        transcript_count: 1,
        challenge_count: 1,
        challenge_cutoff_timestamp_ms: 1_760_000_200,
    };
    let challenge = AsymptoteObserverChallenge {
        challenge_id: [75u8; 32],
        epoch: 8,
        height: 14,
        view: 1,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id: observer,
        assignment: None,
        observation_request: None,
        transcript: None,
        canonical_close: Some(canonical_close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(&canonical_close).unwrap(),
        details: "negative sealing object remains decisive without membership penalties".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(26, 1), (27, 1), (28, 1)])).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "report_asymptote_observer_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(
        &state
            .get(&guardian_registry_observer_challenge_key(
                8,
                14,
                1,
                &[75u8; 32],
            ))
            .unwrap()
            .expect("observer challenge stored"),
    )
    .unwrap();
    assert_eq!(stored_challenge, challenge);
    assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

    let stored_sets = read_validator_sets(
        &state
            .get(VALIDATOR_SET_KEY)
            .unwrap()
            .expect("validator sets stored"),
    )
    .unwrap();
    assert!(stored_sets.next.is_none());
    assert!(stored_sets
        .current
        .validators
        .iter()
        .any(|validator| validator.account_id == producer));

    let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
        &state
            .get(EVIDENCE_REGISTRY_KEY)
            .unwrap()
            .expect("evidence registry stored"),
    )
    .unwrap();
    assert_eq!(evidence_registry.len(), 1);
}

#[test]
fn reporting_aft_omission_remains_published_when_membership_update_attempt_errors() {
    let registry = production_registry();
    let omission = OmissionProof {
        height: 16,
        offender_account_id: AccountId([41u8; 32]),
        tx_hash: [91u8; 32],
        bulletin_root: [92u8; 32],
        details: "ordering omission remains decisive even if penalty staging errors".into(),
    };

    let mut state = MockState::default();
    state
        .insert(VALIDATOR_SET_KEY, &[0xFF, 0x00, 0x01])
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "report_aft_omission@v1",
            &codec::to_bytes_canonical(&omission).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_omission: OmissionProof = codec::from_bytes_canonical(
        &state
            .get(&aft_omission_proof_key(omission.height, &omission.tx_hash))
            .unwrap()
            .expect("omission proof stored"),
    )
    .unwrap();
    assert_eq!(stored_omission, omission);

    let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
        &state
            .get(EVIDENCE_REGISTRY_KEY)
            .unwrap()
            .expect("evidence registry stored"),
    )
    .unwrap();
    assert_eq!(evidence_registry.len(), 1);
}

#[test]
fn reporting_observer_challenge_remains_published_when_membership_update_attempt_errors() {
    let registry = production_registry();
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: 9,
        height: 17,
        view: 1,
        assignments_hash: [93u8; 32],
        transcripts_root: [94u8; 32],
        challenges_root: [95u8; 32],
        transcript_count: 1,
        challenge_count: 1,
        challenge_cutoff_timestamp_ms: 1_780_000_000,
    };
    let challenge = AsymptoteObserverChallenge {
        challenge_id: [96u8; 32],
        epoch: 9,
        height: 17,
        view: 1,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id: AccountId([42u8; 32]),
        assignment: None,
        observation_request: None,
        transcript: None,
        canonical_close: Some(canonical_close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(&canonical_close).unwrap(),
        details: "sealing abort remains decisive even if penalty staging errors".into(),
    };

    let mut state = MockState::default();
    state
        .insert(VALIDATOR_SET_KEY, &[0xFE, 0x00, 0x02])
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "report_asymptote_observer_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(
        &state
            .get(&guardian_registry_observer_challenge_key(
                9,
                17,
                1,
                &[96u8; 32],
            ))
            .unwrap()
            .expect("observer challenge stored"),
    )
    .unwrap();
    assert_eq!(stored_challenge, challenge);

    let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
        &state
            .get(EVIDENCE_REGISTRY_KEY)
            .unwrap()
            .expect("evidence registry stored"),
    )
    .unwrap();
    assert_eq!(evidence_registry.len(), 1);
}

#[test]
fn accountable_fault_skips_immediate_quarantine_when_current_liveness_would_break() {
    let registry = production_registry();
    let offender = AccountId([31u8; 32]);
    let omission = OmissionProof {
        height: 15,
        offender_account_id: offender,
        tx_hash: [71u8; 32],
        bulletin_root: [72u8; 32],
        details: "objective omission proof for a two-validator set".into(),
    };

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(31, 1), (32, 1)])).unwrap(),
        )
        .unwrap();

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "report_aft_omission@v1",
            &codec::to_bytes_canonical(&omission).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

    let stored_sets = read_validator_sets(
        &state
            .get(VALIDATOR_SET_KEY)
            .unwrap()
            .expect("validator sets stored"),
    )
    .unwrap();
    let next = stored_sets.next.expect("next validator set staged");
    assert_eq!(next.validators.len(), 1);
    assert!(!next
        .validators
        .iter()
        .any(|validator| validator.account_id == offender));
}

#[test]
fn publishing_observer_canonical_sealing_artifacts_persists_registry_state() {
    let registry = production_registry();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: 7,
        height: 12,
        view: 3,
        assignments_hash: [1u8; 32],
        transcripts_root: [2u8; 32],
        transcript_count: 2,
    };
    let transcript = AsymptoteObserverTranscript {
        statement: AsymptoteObserverStatement {
            epoch: 7,
            assignment: AsymptoteObserverAssignment {
                epoch: 7,
                producer_account_id: AccountId([3u8; 32]),
                height: 12,
                view: 3,
                round: 0,
                observer_account_id: AccountId([4u8; 32]),
            },
            block_hash: [5u8; 32],
            guardian_manifest_hash: [6u8; 32],
            guardian_decision_hash: [7u8; 32],
            guardian_counter: 8,
            guardian_trace_hash: [9u8; 32],
            guardian_measurement_root: [10u8; 32],
            guardian_checkpoint_root: [11u8; 32],
            verdict: AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [12u8; 32],
        },
        guardian_certificate: GuardianQuorumCertificate {
            manifest_hash: [13u8; 32],
            epoch: 7,
            decision_hash: [14u8; 32],
            ..Default::default()
        },
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: 7,
        height: 12,
        view: 3,
        challenges_root: [15u8; 32],
        challenge_count: 1,
    };
    let evidence_hash = canonical_asymptote_observer_transcript_hash(&transcript).unwrap();
    let challenge = AsymptoteObserverChallenge {
        challenge_id: [16u8; 32],
        epoch: 7,
        height: 12,
        view: 3,
        kind: AsymptoteObserverChallengeKind::VetoTranscriptPresent,
        challenger_account_id: AccountId([17u8; 32]),
        assignment: Some(transcript.statement.assignment.clone()),
        observation_request: None,
        transcript: Some(transcript.clone()),
        canonical_close: None,
        evidence_hash,
        details: "published veto transcript dominates close".into(),
    };
    let refreshed_challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: 7,
        height: 12,
        view: 3,
        challenges_root: canonical_asymptote_observer_challenges_hash(std::slice::from_ref(
            &challenge,
        ))
        .expect("observer challenge root"),
        challenge_count: 1,
    };
    let abort = AsymptoteObserverCanonicalAbort {
        epoch: 7,
        height: 12,
        view: 3,
        assignments_hash: [19u8; 32],
        transcripts_root: [20u8; 32],
        challenges_root: [21u8; 32],
        transcript_count: 1,
        challenge_count: 1,
        challenge_cutoff_timestamp_ms: 1_750_000_100,
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_asymptote_observer_transcript_commitment@v1",
            &codec::to_bytes_canonical(&transcript_commitment).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_asymptote_observer_transcript@v1",
            &codec::to_bytes_canonical(&transcript).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_asymptote_observer_challenge_commitment@v1",
            &codec::to_bytes_canonical(&challenge_commitment).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "report_asymptote_observer_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_asymptote_observer_canonical_abort@v1",
            &codec::to_bytes_canonical(&abort).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let stored_transcript_commitment = state
        .get(&guardian_registry_observer_transcript_commitment_key(
            7, 12, 3,
        ))
        .unwrap()
        .expect("transcript commitment stored");
    let restored_transcript_commitment: AsymptoteObserverTranscriptCommitment =
        codec::from_bytes_canonical(&stored_transcript_commitment).unwrap();
    assert_eq!(restored_transcript_commitment, transcript_commitment);

    let stored_transcript = state
        .get(&guardian_registry_observer_transcript_key(
            7,
            12,
            3,
            0,
            &AccountId([4u8; 32]),
        ))
        .unwrap()
        .expect("observer transcript stored");
    let restored_transcript: AsymptoteObserverTranscript =
        codec::from_bytes_canonical(&stored_transcript).unwrap();
    assert_eq!(restored_transcript, transcript);

    let stored_challenge_commitment = state
        .get(&guardian_registry_observer_challenge_commitment_key(
            7, 12, 3,
        ))
        .unwrap()
        .expect("challenge commitment stored");
    let restored_challenge_commitment: AsymptoteObserverChallengeCommitment =
        codec::from_bytes_canonical(&stored_challenge_commitment).unwrap();
    assert_eq!(
        restored_challenge_commitment,
        refreshed_challenge_commitment
    );

    let stored_challenge = state
        .get(&guardian_registry_observer_challenge_key(
            7,
            12,
            3,
            &[16u8; 32],
        ))
        .unwrap()
        .expect("observer challenge stored");
    let restored_challenge: AsymptoteObserverChallenge =
        codec::from_bytes_canonical(&stored_challenge).unwrap();
    assert_eq!(restored_challenge, challenge);

    let stored_abort = state
        .get(&guardian_registry_observer_canonical_abort_key(7, 12, 3))
        .unwrap()
        .expect("canonical abort stored");
    let restored_abort: AsymptoteObserverCanonicalAbort =
        codec::from_bytes_canonical(&stored_abort).unwrap();
    assert_eq!(restored_abort, abort);
}

#[test]
fn observer_canonical_abort_dominates_close_but_close_cannot_override_abort() {
    let registry = production_registry();
    let close = AsymptoteObserverCanonicalClose {
        epoch: 9,
        height: 22,
        view: 1,
        assignments_hash: [81u8; 32],
        transcripts_root: [82u8; 32],
        challenges_root: [83u8; 32],
        transcript_count: 1,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 1_770_000_000,
    };
    let abort = AsymptoteObserverCanonicalAbort {
        epoch: 9,
        height: 22,
        view: 1,
        assignments_hash: [81u8; 32],
        transcripts_root: [82u8; 32],
        challenges_root: [84u8; 32],
        transcript_count: 1,
        challenge_count: 1,
        challenge_cutoff_timestamp_ms: 1_770_000_100,
    };

    let mut close_first_state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut close_first_state,
            "publish_asymptote_observer_canonical_close@v1",
            &codec::to_bytes_canonical(&close).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut close_first_state,
            "publish_asymptote_observer_canonical_abort@v1",
            &codec::to_bytes_canonical(&abort).unwrap(),
            ctx,
        ))
        .unwrap();
    });
    assert!(close_first_state
        .get(&guardian_registry_observer_canonical_close_key(9, 22, 1))
        .unwrap()
        .is_none());
    let stored_abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(
        &close_first_state
            .get(&guardian_registry_observer_canonical_abort_key(9, 22, 1))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(stored_abort, abort);

    let mut abort_first_state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut abort_first_state,
            "publish_asymptote_observer_canonical_abort@v1",
            &codec::to_bytes_canonical(&abort).unwrap(),
            ctx,
        ))
        .unwrap();
        let err = run_async(registry.handle_service_call(
            &mut abort_first_state,
            "publish_asymptote_observer_canonical_close@v1",
            &codec::to_bytes_canonical(&close).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("canonical abort is already persisted"));
    });
}

#[test]
fn reporting_observer_challenge_materializes_challenge_commitment_and_abort_from_close() {
    let registry = production_registry();
    let close = AsymptoteObserverCanonicalClose {
        epoch: 11,
        height: 24,
        view: 2,
        assignments_hash: [101u8; 32],
        transcripts_root: [102u8; 32],
        challenges_root: [0u8; 32],
        transcript_count: 1,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 1_780_000_500,
    };
    let challenge = AsymptoteObserverChallenge {
        challenge_id: [103u8; 32],
        epoch: 11,
        height: 24,
        view: 2,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id: AccountId([104u8; 32]),
        assignment: None,
        observation_request: None,
        transcript: None,
        canonical_close: Some(close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(&close).unwrap(),
        details: "late challenge dominates previously published close".into(),
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_asymptote_observer_canonical_close@v1",
            &codec::to_bytes_canonical(&close).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "report_asymptote_observer_challenge@v1",
            &codec::to_bytes_canonical(&challenge).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert!(state
        .get(&guardian_registry_observer_canonical_close_key(11, 24, 2))
        .unwrap()
        .is_none());
    let stored_commitment: AsymptoteObserverChallengeCommitment = codec::from_bytes_canonical(
        &state
            .get(&guardian_registry_observer_challenge_commitment_key(
                11, 24, 2,
            ))
            .unwrap()
            .expect("challenge commitment stored"),
    )
    .unwrap();
    assert_eq!(stored_commitment.challenge_count, 1);
    let stored_abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(
        &state
            .get(&guardian_registry_observer_canonical_abort_key(11, 24, 2))
            .unwrap()
            .expect("abort stored"),
    )
    .unwrap();
    assert_eq!(stored_abort.assignments_hash, close.assignments_hash);
    assert_eq!(stored_abort.transcripts_root, close.transcripts_root);
    assert_eq!(
        stored_abort.challenges_root,
        stored_commitment.challenges_root
    );
    assert_eq!(stored_abort.challenge_count, 1);
    assert_eq!(
        stored_abort.challenge_cutoff_timestamp_ms,
        close.challenge_cutoff_timestamp_ms
    );
}

#[test]
fn canonical_observer_policy_requires_non_zero_challenge_window() {
    let registry = production_registry();
    let policy = AsymptotePolicy {
        epoch: 3,
        observer_rounds: 1,
        observer_committee_size: 1,
        observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
        ..Default::default()
    };

    let mut state = MockState::default();
    let mut err = None;
    with_ctx(|ctx| {
        err = Some(
            run_async(registry.handle_service_call(
                &mut state,
                "publish_asymptote_policy@v1",
                &codec::to_bytes_canonical(&policy).unwrap(),
                ctx,
            ))
            .unwrap_err(),
        );
    });
    let err = err.expect("policy publication should fail");

    assert!(err
        .to_string()
        .contains("canonical observer sealing mode requires a non-zero challenge window"));
}
