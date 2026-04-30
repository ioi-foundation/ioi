#[tokio::test]
async fn asymptote_rejects_invalid_canonical_close_challenge_when_close_is_valid() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let observer_transcripts = fixture.observer_transcripts.clone();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let empty_challenges: Vec<AsymptoteObserverChallenge> = Vec::new();
    let empty_challenges_root =
        canonical_asymptote_observer_challenges_hash(&empty_challenges).unwrap();
    let valid_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root: empty_challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 35_000,
    };
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id: fixture.header.producer_account_id,
        assignment: None,
        observation_request: None,
        transcript: None,
        canonical_close: Some(valid_close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(&valid_close).unwrap(),
        details: "claiming a valid close is invalid should fail".into(),
    };
    finalize_observer_challenge_id(&mut challenge);
    let observer_challenges = vec![challenge];
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: observer_challenges.len() as u16,
    };
    let canonical_abort = AsymptoteObserverCanonicalAbort {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: observer_challenges.len() as u16,
        challenge_cutoff_timestamp_ms: 35_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::BaseFinal,
        collapse_state: CollapseState::Abort,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment),
        observer_challenge_commitment: Some(challenge_commitment),
        observer_canonical_close: None,
        observer_canonical_abort: Some(canonical_abort),
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let parent_view = canonical_observer_parent_view(&fixture);
    let err = fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err.to_string().contains(
        "invalid-canonical-close challenge does not contain an objectively invalid close"
    ));
}

#[tokio::test]
async fn asymptote_rejects_sealed_final_canonical_close_when_challenge_surface_is_non_empty() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let challenged_assignment = fixture.observer_assignments[0].clone();
    let observer_transcripts = fixture
        .observer_transcripts
        .iter()
        .filter(|transcript| transcript.statement.assignment != challenged_assignment)
        .cloned()
        .collect::<Vec<_>>();
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        kind: AsymptoteObserverChallengeKind::MissingTranscript,
        challenger_account_id: fixture.header.producer_account_id,
        assignment: Some(challenged_assignment),
        observation_request: None,
        transcript: None,
        canonical_close: None,
        evidence_hash: canonical_asymptote_observer_assignment_hash(
            &fixture.observer_assignments[0],
        )
        .unwrap(),
        details: "observer transcript missing at close".into(),
    };
    finalize_observer_challenge_id(&mut challenge);
    let observer_challenges = vec![challenge];
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: observer_challenges.len() as u16,
    };
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: observer_challenges.len() as u16,
        challenge_cutoff_timestamp_ms: 33_000,
    };

    fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: fixture.manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: fixture.manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment),
        observer_challenge_commitment: Some(challenge_commitment),
        observer_canonical_close: Some(canonical_close),
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let parent_view = canonical_observer_parent_view(&fixture);
    let err = fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap_err();
    let err_text = err.to_string();
    assert!(
        err_text.contains(
            "observer challenge surface is non-empty; canonical close is challenge-dominated"
        ) || err_text.contains("canonical observer close may not carry dominant challenges")
            || err_text.contains(
                "observer transcript counts do not match the deterministic assignment surface"
            ),
        "unexpected canonical-close rejection: {err_text}"
    );
}

#[tokio::test]
async fn asymptote_accepts_valid_canonical_order_certificate() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_001,
        bulletin_root: [61u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [63u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let mut parent_view = parent_view;
    let bulletin_availability_certificate = header
        .canonical_order_certificate
        .as_ref()
        .unwrap()
        .bulletin_availability_certificate
        .clone();
    parent_view.state.insert(
        aft_bulletin_availability_certificate_key(header.height),
        codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
    );
    let bulletin_close = build_canonical_bulletin_close(
        &header
            .canonical_order_certificate
            .as_ref()
            .unwrap()
            .bulletin_commitment,
        &bulletin_availability_certificate,
    )
    .unwrap();
    parent_view.state.insert(
        aft_canonical_bulletin_close_key(header.height),
        codec::to_bytes_canonical(&bulletin_close).unwrap(),
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_with_mismatched_published_availability() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_001,
        bulletin_root: [81u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [82u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let mut mismatched_availability = header
        .canonical_order_certificate
        .as_ref()
        .unwrap()
        .bulletin_availability_certificate
        .clone();
    mismatched_availability.recoverability_root = [83u8; 32];
    parent_view.state.insert(
        aft_bulletin_availability_certificate_key(header.height),
        codec::to_bytes_canonical(&mismatched_availability).unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err.to_string().contains(
            "canonical order certificate bulletin availability certificate does not match published bulletin availability"
        ));
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_with_mismatched_published_bulletin_close() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_011,
        bulletin_root: [91u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate: bulletin_availability_certificate.clone(),
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [92u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    parent_view.state.insert(
        aft_bulletin_availability_certificate_key(header.height),
        codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
    );
    let mut mismatched_bulletin_close = build_canonical_bulletin_close(
        &header
            .canonical_order_certificate
            .as_ref()
            .unwrap()
            .bulletin_commitment,
        &bulletin_availability_certificate,
    )
    .unwrap();
    mismatched_bulletin_close.entry_count = mismatched_bulletin_close.entry_count.saturating_add(1);
    parent_view.state.insert(
        aft_canonical_bulletin_close_key(header.height),
        codec::to_bytes_canonical(&mismatched_bulletin_close).unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("canonical bulletin close entry count does not match the bulletin commitment"));
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_with_omission_proof() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_002,
        bulletin_root: [71u8; 32],
        entry_count: 2,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: vec![OmissionProof {
            height: header.height,
            offender_account_id: manifest.validator_account_id,
            tx_hash: [73u8; 32],
            bulletin_root: bulletin.bulletin_root,
            details: "omitted from canonical order".into(),
        }],
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [74u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("canonical order certificate is dominated by objective omission proofs"));
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_when_published_abort_exists() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_021,
        bulletin_root: [101u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [102u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    parent_view.state.insert(
        aft_canonical_order_abort_key(header.height),
        codec::to_bytes_canonical(&CanonicalOrderAbort {
            height: header.height,
            reason: CanonicalOrderAbortReason::InvalidProofBinding,
            details: "published canonical abort dominates a proof-binding failure".into(),
            bulletin_commitment_hash: [103u8; 32],
            bulletin_availability_certificate_hash: [104u8; 32],
            bulletin_close_hash: [106u8; 32],
            canonical_order_certificate_hash: [105u8; 32],
        })
        .unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("canonical order abort already dominates slot"));
}

#[tokio::test]
async fn asymptote_rejects_canonical_order_certificate_without_publication_frontier() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_026,
        bulletin_root: [107u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [108u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("requires a publication frontier"));
}

#[tokio::test]
async fn asymptote_rejects_conflicting_published_publication_frontier() {
    let (mut engine, mut header, manifest, preimage, _, log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_027,
        bulletin_root: [109u8; 32],
        entry_count: 3,
    };
    let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
    let template_certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment: bulletin.clone(),
        bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
        randomness_beacon,
        ordered_transactions_root_hash: [0u8; 32],
        resulting_state_root_hash: [0u8; 32],
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash: [0u8; 32],
            proof_bytes: Vec::new(),
        },
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin,
        &randomness_beacon,
        &public_inputs.ordered_transactions_root_hash,
        &public_inputs.resulting_state_root_hash,
    )
    .unwrap();
    header.canonical_order_certificate = Some(CanonicalOrderCertificate {
        bulletin_availability_certificate,
        ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
        resulting_state_root_hash: public_inputs.resulting_state_root_hash,
        proof: CanonicalOrderProof {
            proof_system: CanonicalOrderProofSystem::HashBindingV1,
            public_inputs_hash,
            proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash).unwrap(),
        },
        ..template_certificate
    });
    let frontier = build_publication_frontier(&header, None).unwrap();
    header.publication_frontier = Some(frontier.clone());

    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [110u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let mut conflicting_frontier = frontier.clone();
    conflicting_frontier.view += 1;
    conflicting_frontier.bulletin_commitment_hash[0] ^= 0xFF;
    parent_view.state.insert(
        aft_publication_frontier_key(header.height),
        codec::to_bytes_canonical(&conflicting_frontier).unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("conflicts with the published same-slot frontier"));
}

#[tokio::test]
async fn asymptote_accepts_abort_only_ordering_outcome_when_abort_is_published() {
    let (mut engine, header, manifest, preimage, _, log_keypair) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_031,
        bulletin_root: [111u8; 32],
        entry_count: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [112u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    parent_view.state.insert(
        aft_canonical_order_abort_key(header.height),
        codec::to_bytes_canonical(&CanonicalOrderAbort {
            height: header.height,
            reason: CanonicalOrderAbortReason::BulletinSurfaceMismatch,
            details: "published canonical abort is the ordering outcome after a surface mismatch"
                .into(),
            bulletin_commitment_hash: [113u8; 32],
            bulletin_availability_certificate_hash: [114u8; 32],
            bulletin_close_hash: [115u8; 32],
            canonical_order_certificate_hash: [116u8; 32],
        })
        .unwrap(),
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_abort_only_outcome_when_parent_state_coexists_with_positive_ordering_artifacts(
) {
    let (mut engine, header, manifest, preimage, _, log_keypair) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_041,
        bulletin_root: [121u8; 32],
        entry_count: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [122u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin.clone(),
    );
    let bulletin_availability_certificate = BulletinAvailabilityCertificate {
        height: header.height,
        bulletin_commitment_hash: [123u8; 32],
        recoverability_root: [124u8; 32],
    };
    parent_view.state.insert(
        aft_bulletin_availability_certificate_key(header.height),
        codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
    );
    let bulletin_close =
        build_canonical_bulletin_close(&bulletin, &bulletin_availability_certificate).unwrap();
    parent_view.state.insert(
        aft_canonical_bulletin_close_key(header.height),
        codec::to_bytes_canonical(&bulletin_close).unwrap(),
    );
    parent_view.state.insert(
        aft_canonical_order_abort_key(header.height),
        codec::to_bytes_canonical(&CanonicalOrderAbort {
            height: header.height,
            reason: CanonicalOrderAbortReason::MissingOrderCertificate,
            details: "abort should not coexist with positive ordering artifacts".into(),
            bulletin_commitment_hash: [125u8; 32],
            bulletin_availability_certificate_hash: [126u8; 32],
            bulletin_close_hash: [127u8; 32],
            canonical_order_certificate_hash: [0u8; 32],
        })
        .unwrap(),
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("canonical order abort coexists with positive published ordering artifacts"));
}

#[tokio::test]
async fn asymptote_accepts_matching_published_canonical_collapse_object() {
    let (mut engine, header, manifest, _preimage, _, log_keypair) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_051,
        bulletin_root: [131u8; 32],
        entry_count: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [132u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let previous =
        test_canonical_collapse_object(header.height - 1, None, [210u8; 32], [211u8; 32]);
    parent_view.state.insert(
        aft_canonical_collapse_object_key(previous.height),
        codec::to_bytes_canonical(&previous).unwrap(),
    );
    let collapse =
        derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous)).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(header.height),
        codec::to_bytes_canonical(&collapse).unwrap(),
    );

    engine
        .verify_published_canonical_collapse_object(&header, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_mismatched_published_canonical_collapse_object() {
    let (mut engine, header, manifest, _preimage, _, log_keypair) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;

    let bulletin = BulletinCommitment {
        height: header.height,
        cutoff_timestamp_ms: 1_750_000_061,
        bulletin_root: [141u8; 32],
        entry_count: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: vec!["stratum-a".into()],
        escalation_witness_strata: vec!["stratum-a".into()],
        observer_rounds: 0,
        observer_committee_size: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
    };
    let mut parent_view = build_parent_view_with_bulletin_commitment(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &log_keypair,
        )],
        policy,
        GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [142u8; 32],
            checkpoint_interval_blocks: 4,
            max_reassignment_depth: 0,
        },
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .clone()
            .unwrap()],
        bulletin,
    );
    let previous =
        test_canonical_collapse_object(header.height - 1, None, [212u8; 32], [213u8; 32]);
    parent_view.state.insert(
        aft_canonical_collapse_object_key(previous.height),
        codec::to_bytes_canonical(&previous).unwrap(),
    );
    let mut collapse =
        derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous)).unwrap();
    collapse.resulting_state_root_hash = [143u8; 32];
    parent_view.state.insert(
        aft_canonical_collapse_object_key(header.height),
        codec::to_bytes_canonical(&collapse).unwrap(),
    );

    let err = engine
        .verify_published_canonical_collapse_object(&header, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("published canonical collapse object does not match"));
}

#[tokio::test]
async fn asymptote_rejects_valid_equal_authority_veto_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: manifest.epoch,
        seed: [92u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: Vec::new(),
        escalation_witness_strata: Vec::new(),
        observer_rounds: 1,
        observer_committee_size: 1,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
    };
    let validators = vec![
        header.producer_account_id,
        AccountId([41u8; 32]),
        AccountId([42u8; 32]),
    ];
    let assignment = derive_asymptote_observer_assignments(
        &witness_seed,
        &build_validator_sets(validators.clone()).current,
        header.producer_account_id,
        header.height,
        header.view,
        policy.observer_rounds,
        policy.observer_committee_size,
    )
    .unwrap()
    .into_iter()
    .next()
    .unwrap();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(std::slice::from_ref(&assignment)).unwrap();
    let mut observer_manifests = Vec::new();
    let mut selected_manifest = None;
    let mut selected_member_keys = None;
    for account in validators
        .iter()
        .copied()
        .filter(|account| *account != header.producer_account_id)
    {
        let member_keys = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let observer_manifest = build_observer_manifest(
            account,
            manifest.epoch,
            [62u8; 32],
            &format!("observer-veto-{}", hex::encode(account.as_ref())),
            &member_keys,
        );
        if account == assignment.observer_account_id {
            selected_manifest = Some(observer_manifest.clone());
            selected_member_keys = Some(member_keys);
        }
        observer_manifests.push(observer_manifest);
    }
    let observer_manifest = selected_manifest.unwrap();
    let member_keys = selected_member_keys.unwrap();
    let provisional = AsymptoteObserverCertificate {
        assignment: assignment.clone(),
        verdict: AsymptoteObserverVerdict::Veto,
        veto_kind: Some(AsymptoteVetoKind::ConflictingGuardianCertificate),
        evidence_hash: [7u8; 32],
        guardian_certificate: GuardianQuorumCertificate::default(),
    };
    let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let statement = engine
        .asymptote_observer_statement(&header, &base_certificate, &provisional)
        .unwrap();
    let decision = GuardianDecision {
        domain: GuardianDecisionDomain::AsymptoteObserve as u8,
        subject: assignment.observer_account_id.0.to_vec(),
        payload_hash: ioi_crypto::algorithms::hash::sha256(
            &codec::to_bytes_canonical(&statement).unwrap(),
        )
        .unwrap(),
        counter: 1,
        trace_hash: [4u8; 32],
        measurement_root: observer_manifest.measurement_profile_root,
        policy_hash: observer_manifest.policy_hash,
    };
    let observer_log_keypair = Keypair::generate_ed25519();
    let mut observer_guardian_certificate = sign_decision_with_members(
        &observer_manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &[
            (0, member_keys[0].private_key()),
            (1, member_keys[1].private_key()),
        ],
    )
    .unwrap();
    let checkpoint_entry =
        codec::to_bytes_canonical(&(decision.clone(), observer_guardian_certificate.clone()))
            .unwrap();
    observer_guardian_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &observer_manifest.transparency_log_id,
        &observer_log_keypair,
        &[checkpoint_entry],
        0,
        1,
    ));
    let veto_proof = AsymptoteVetoProof {
        observer_certificate: AsymptoteObserverCertificate {
            assignment,
            verdict: AsymptoteObserverVerdict::Veto,
            veto_kind: Some(AsymptoteVetoKind::ConflictingGuardianCertificate),
            evidence_hash: [7u8; 32],
            guardian_certificate: observer_guardian_certificate.clone(),
        },
        details: "conflicting guardian-backed slot evidence".into(),
    };
    let anchored_checkpoints = vec![
        base_certificate.log_checkpoint.as_ref().unwrap().clone(),
        observer_guardian_certificate
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone(),
    ];

    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: base_certificate.manifest_hash,
        guardian_decision_hash: base_certificate.decision_hash,
        guardian_counter: base_certificate.counter,
        guardian_trace_hash: base_certificate.trace_hash,
        guardian_measurement_root: base_certificate.measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: Some(AsymptoteObserverCloseCertificate {
            epoch: manifest.epoch,
            height: header.height,
            view: header.view,
            assignments_hash: observer_assignments_hash,
            expected_assignments: 1,
            ok_count: 0,
            veto_count: 1,
        }),
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: vec![veto_proof],
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let parent_view = build_parent_view_with_asymptote_observers(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &observer_manifest.transparency_log_id,
                &observer_log_keypair,
            ),
        ],
        policy,
        witness_seed,
        &anchored_checkpoints,
        validators,
        &observer_manifests,
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn guardian_majority_rejects_checkpoint_log_id_mismatch() {
    let (engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    header.guardian_certificate.as_mut().unwrap().log_checkpoint = Some(GuardianLogCheckpoint {
        log_id: "wrong-log".into(),
        tree_size: 1,
        root_hash: [11u8; 32],
        timestamp_ms: 11,
        signature: vec![1],
        proof: None,
    });
    let parent_view = build_parent_view(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &guardian_log_keypair,
        )],
        &[],
        GuardianWitnessSet::default(),
        GuardianWitnessEpochSeed::default(),
        &[],
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn guardian_majority_rejects_checkpoint_rollback_against_anchor() {
    let (engine, header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    let guardian_entry = codec::to_bytes_canonical(&(
        GuardianDecision {
            domain: GuardianDecisionDomain::ConsensusSlot as u8,
            subject: manifest.validator_account_id.0.to_vec(),
            payload_hash: ioi_crypto::algorithms::hash::sha256(&preimage).unwrap(),
            counter: header.oracle_counter,
            trace_hash: header.oracle_trace_hash,
            measurement_root: manifest.measurement_profile_root,
            policy_hash: manifest.policy_hash,
        },
        {
            let mut checkpoint_certificate = header.guardian_certificate.as_ref().unwrap().clone();
            checkpoint_certificate.log_checkpoint = None;
            checkpoint_certificate.experimental_witness_certificate = None;
            checkpoint_certificate
        },
    ))
    .unwrap();
    let parent_view = build_parent_view(
        &manifest,
        &[build_log_descriptor(
            &manifest.transparency_log_id,
            &guardian_log_keypair,
        )],
        &[],
        GuardianWitnessSet::default(),
        GuardianWitnessEpochSeed::default(),
        &[build_signed_checkpoint(
            &manifest.transparency_log_id,
            &guardian_log_keypair,
            &[guardian_entry.clone(), b"anchor-2".to_vec()],
            1,
            20,
        )],
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn experimental_nested_guardian_rejects_witness_checkpoint_rollback_against_anchor() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest = build_witness_manifest(&witness_members);
    let witness_hash = canonical_witness_manifest_hash(&witness_manifest).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest.epoch,
        manifest_hashes: vec![witness_hash],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest.epoch,
        seed: [42u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 1,
    };
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let mut witness_certificate = sign_witness_statement_with_members(
        &witness_manifest,
        &statement,
        &[
            (0, witness_members[0].private_key()),
            (1, witness_members[1].private_key()),
            (2, witness_members[2].private_key()),
        ],
    )
    .unwrap();
    let witness_checkpoint_entry =
        codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
    witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &witness_manifest.transparency_log_id,
        &witness_log_keypair,
        std::slice::from_ref(&witness_checkpoint_entry),
        0,
        10,
    ));
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .experimental_witness_certificate = Some(witness_certificate);
    let parent_view = build_parent_view(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(&witness_manifest.transparency_log_id, &witness_log_keypair),
        ],
        &[witness_manifest.clone()],
        witness_set,
        witness_seed,
        &[
            header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
            GuardianLogCheckpoint {
                ..build_signed_checkpoint(
                    &witness_manifest.transparency_log_id,
                    &witness_log_keypair,
                    &[witness_checkpoint_entry, b"witness-anchor-2".to_vec()],
                    1,
                    20,
                )
            },
        ],
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

