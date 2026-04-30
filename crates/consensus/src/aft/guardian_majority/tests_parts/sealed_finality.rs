#[tokio::test]
async fn asymptote_accepts_valid_sealed_finality_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members_a = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_members_b = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest_a = build_witness_manifest(&witness_members_a);
    let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
    witness_manifest_b.committee_id = "witness-b".into();
    witness_manifest_b.stratum_id = "stratum-b".into();
    witness_manifest_b.transparency_log_id = "witness-test-b".into();

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [77u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        2,
    )
    .unwrap();
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let mut witness_certificates = Vec::new();
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    for assignment in assignments {
        let (assigned_manifest, assigned_members) = if assignment.manifest_hash == witness_hash_a {
            (&witness_manifest_a, &witness_members_a)
        } else {
            (&witness_manifest_b, &witness_members_b)
        };
        let mut witness_certificate = sign_witness_statement_with_members(
            assigned_manifest,
            &statement,
            &[
                (0, assigned_members[0].private_key()),
                (1, assigned_members[1].private_key()),
                (2, assigned_members[2].private_key()),
            ],
        )
        .unwrap();
        let witness_checkpoint_entry =
            codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
        witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &assigned_manifest.transparency_log_id,
            &witness_log_keypair,
            std::slice::from_ref(&witness_checkpoint_entry),
            0,
            1,
        ));
        anchored_checkpoints.push(witness_certificate.log_checkpoint.clone().unwrap());
        witness_certificates.push(witness_certificate);
    }
    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: header.guardian_certificate.as_ref().unwrap().manifest_hash,
        guardian_decision_hash: header.guardian_certificate.as_ref().unwrap().decision_hash,
        guardian_counter: header.oracle_counter,
        guardian_trace_hash: header.oracle_trace_hash,
        guardian_measurement_root: header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates,
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let parent_view = build_parent_view_with_asymptote_policy(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &witness_manifest_a.transparency_log_id,
                &witness_log_keypair,
            ),
            build_log_descriptor(
                &witness_manifest_b.transparency_log_id,
                &witness_log_keypair,
            ),
        ],
        &[witness_manifest_a, witness_manifest_b],
        witness_set,
        witness_seed,
        &anchored_checkpoints,
        AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: vec!["stratum-a".into(), "stratum-b".into()],
            escalation_witness_strata: vec![
                "stratum-a".into(),
                "stratum-b".into(),
                "stratum-c".into(),
            ],
            observer_rounds: 0,
            observer_committee_size: 0,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        },
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_sealed_finality_proof_with_distinct_recovery_bindings() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members_a = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_members_b = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest_a = build_witness_manifest(&witness_members_a);
    let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
    witness_manifest_b.committee_id = "witness-b".into();
    witness_manifest_b.stratum_id = "stratum-b".into();
    witness_manifest_b.transparency_log_id = "witness-test-b".into();

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [79u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        2,
    )
    .unwrap();
    let recovery_capsule_hash = [0x91u8; 32];
    let mut witness_certificates = Vec::new();
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    for (index, assignment) in assignments.into_iter().enumerate() {
        let (assigned_manifest, assigned_members) = if assignment.manifest_hash == witness_hash_a {
            (&witness_manifest_a, &witness_members_a)
        } else {
            (&witness_manifest_b, &witness_members_b)
        };
        let recovery_binding = GuardianWitnessRecoveryBinding {
            recovery_capsule_hash,
            share_commitment_hash: [0xA0u8.saturating_add(index as u8); 32],
        };
        let statement = ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
            &header,
            header.guardian_certificate.as_ref().unwrap(),
            Some(recovery_binding.clone()),
        );
        let mut witness_certificate = sign_witness_statement_with_members(
            assigned_manifest,
            &statement,
            &[
                (0, assigned_members[0].private_key()),
                (1, assigned_members[1].private_key()),
                (2, assigned_members[2].private_key()),
            ],
        )
        .unwrap();
        let witness_checkpoint_entry =
            codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
        witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &assigned_manifest.transparency_log_id,
            &witness_log_keypair,
            std::slice::from_ref(&witness_checkpoint_entry),
            0,
            1,
        ));
        anchored_checkpoints.push(witness_certificate.log_checkpoint.clone().unwrap());
        witness_certificates.push(witness_certificate);
    }
    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: header.guardian_certificate.as_ref().unwrap().manifest_hash,
        guardian_decision_hash: header.guardian_certificate.as_ref().unwrap().decision_hash,
        guardian_counter: header.oracle_counter,
        guardian_trace_hash: header.oracle_trace_hash,
        guardian_measurement_root: header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates,
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let parent_view = build_parent_view_with_asymptote_policy(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &witness_manifest_a.transparency_log_id,
                &witness_log_keypair,
            ),
            build_log_descriptor(
                &witness_manifest_b.transparency_log_id,
                &witness_log_keypair,
            ),
        ],
        &[witness_manifest_a, witness_manifest_b],
        witness_set,
        witness_seed,
        &anchored_checkpoints,
        AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: vec!["stratum-a".into(), "stratum-b".into()],
            escalation_witness_strata: vec![
                "stratum-a".into(),
                "stratum-b".into(),
                "stratum-c".into(),
            ],
            observer_rounds: 0,
            observer_committee_size: 0,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        },
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_duplicate_witness_committees_in_sealed_finality_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_log_keypair = Keypair::generate_ed25519();

    let witness_members_a = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_members_b = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest_a = build_witness_manifest(&witness_members_a);
    let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
    witness_manifest_b.committee_id = "witness-b".into();
    witness_manifest_b.stratum_id = "stratum-b".into();
    witness_manifest_b.transparency_log_id = "witness-test-b".into();

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [88u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        2,
    )
    .unwrap();
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let first_assignment = assignments.first().unwrap();
    let (assigned_manifest, assigned_members) = if first_assignment.manifest_hash == witness_hash_a
    {
        (&witness_manifest_a, &witness_members_a)
    } else {
        (&witness_manifest_b, &witness_members_b)
    };
    let mut witness_certificate = sign_witness_statement_with_members(
        assigned_manifest,
        &statement,
        &[
            (0, assigned_members[0].private_key()),
            (1, assigned_members[1].private_key()),
            (2, assigned_members[2].private_key()),
        ],
    )
    .unwrap();
    let witness_checkpoint_entry =
        codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
    witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &assigned_manifest.transparency_log_id,
        &witness_log_keypair,
        std::slice::from_ref(&witness_checkpoint_entry),
        0,
        1,
    ));
    let anchored_checkpoints = vec![
        header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone(),
        witness_certificate.log_checkpoint.clone().unwrap(),
    ];
    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: manifest.epoch,
        finality_tier: FinalityTier::SealedFinal,
        collapse_state: CollapseState::SealedFinal,
        guardian_manifest_hash: header.guardian_certificate.as_ref().unwrap().manifest_hash,
        guardian_decision_hash: header.guardian_certificate.as_ref().unwrap().decision_hash,
        guardian_counter: header.oracle_counter,
        guardian_trace_hash: header.oracle_trace_hash,
        guardian_measurement_root: header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .measurement_root,
        policy_hash: manifest.policy_hash,
        witness_certificates: vec![witness_certificate.clone(), witness_certificate],
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );
    let parent_view = build_parent_view_with_asymptote_policy(
        &manifest,
        &[
            guardian_log_descriptor,
            build_log_descriptor(
                &witness_manifest_a.transparency_log_id,
                &witness_log_keypair,
            ),
            build_log_descriptor(
                &witness_manifest_b.transparency_log_id,
                &witness_log_keypair,
            ),
        ],
        &[witness_manifest_a, witness_manifest_b],
        witness_set,
        witness_seed,
        &anchored_checkpoints,
        AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: vec!["stratum-a".into(), "stratum-b".into()],
            escalation_witness_strata: vec![
                "stratum-a".into(),
                "stratum-b".into(),
                "stratum-c".into(),
            ],
            observer_rounds: 0,
            observer_committee_size: 0,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        },
    );

    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn asymptote_accepts_equal_authority_observer_sealed_finality_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: manifest.epoch,
        seed: [91u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: Vec::new(),
        escalation_witness_strata: Vec::new(),
        observer_rounds: 2,
        observer_committee_size: 1,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
        observer_challenge_window_ms: 0,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
    };
    let validators = vec![
        header.producer_account_id,
        AccountId([31u8; 32]),
        AccountId([32u8; 32]),
        AccountId([33u8; 32]),
    ];
    let observer_assignments = derive_asymptote_observer_assignments(
        &witness_seed,
        &build_validator_sets(validators.clone()).current,
        header.producer_account_id,
        header.height,
        header.view,
        policy.observer_rounds,
        policy.observer_committee_size,
    )
    .unwrap();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&observer_assignments).unwrap();

    let observer_log_keypair = Keypair::generate_ed25519();
    let mut observer_manifests = Vec::new();
    let mut observer_descriptors = vec![guardian_log_descriptor];
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    let mut observer_certificates = Vec::new();
    let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let selected_accounts = observer_assignments
        .iter()
        .map(|assignment| assignment.observer_account_id)
        .collect::<std::collections::HashSet<_>>();
    let mut selected_manifests = HashMap::new();
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
        let log_id = format!("observer-{}", hex::encode(account.as_ref()));
        let observer_manifest =
            build_observer_manifest(account, manifest.epoch, [61u8; 32], &log_id, &member_keys);
        if selected_accounts.contains(&account) {
            selected_manifests.insert(account, (observer_manifest.clone(), member_keys));
        }
        observer_manifests.push(observer_manifest);
    }
    for assignment in observer_assignments {
        let (observer_manifest, member_keys) = selected_manifests
            .remove(&assignment.observer_account_id)
            .unwrap();
        let provisional = AsymptoteObserverCertificate {
            assignment: assignment.clone(),
            verdict: AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [0u8; 32],
            guardian_certificate: GuardianQuorumCertificate::default(),
        };
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
            counter: u64::from(assignment.round) + 1,
            trace_hash: [assignment.round as u8 + 1; 32],
            measurement_root: observer_manifest.measurement_profile_root,
            policy_hash: observer_manifest.policy_hash,
        };
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
            u64::from(assignment.round) + 1,
        ));
        anchored_checkpoints.push(
            observer_guardian_certificate
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
        );
        observer_descriptors.push(build_log_descriptor(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
        ));
        observer_certificates.push(AsymptoteObserverCertificate {
            assignment,
            verdict: AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [0u8; 32],
            guardian_certificate: observer_guardian_certificate,
        });
    }

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
        observer_certificates,
        observer_close_certificate: Some(AsymptoteObserverCloseCertificate {
            epoch: manifest.epoch,
            height: header.height,
            view: header.view,
            assignments_hash: observer_assignments_hash,
            expected_assignments: 2,
            ok_count: 2,
            veto_count: 0,
        }),
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let parent_view = build_parent_view_with_asymptote_observers(
        &manifest,
        &observer_descriptors,
        policy,
        witness_seed,
        &anchored_checkpoints,
        validators,
        &observer_manifests,
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_canonical_observer_sealed_finality_proof() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::Asymptote;
    let guardian_log_descriptor =
        build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: manifest.epoch,
        seed: [101u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 0,
    };
    let policy = AsymptotePolicy {
        epoch: manifest.epoch,
        high_risk_effect_tier: FinalityTier::SealedFinal,
        required_witness_strata: Vec::new(),
        escalation_witness_strata: Vec::new(),
        observer_rounds: 2,
        observer_committee_size: 1,
        observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
        observer_challenge_window_ms: 5_000,
        max_reassignment_depth: 0,
        max_checkpoint_staleness_ms: 120_000,
    };
    let validators = vec![
        header.producer_account_id,
        AccountId([51u8; 32]),
        AccountId([52u8; 32]),
        AccountId([53u8; 32]),
    ];
    let observer_assignments = derive_asymptote_observer_assignments(
        &witness_seed,
        &build_validator_sets(validators.clone()).current,
        header.producer_account_id,
        header.height,
        header.view,
        policy.observer_rounds,
        policy.observer_committee_size,
    )
    .unwrap();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&observer_assignments).unwrap();

    let observer_log_keypair = Keypair::generate_ed25519();
    let mut observer_manifests = Vec::new();
    let mut observer_descriptors = vec![guardian_log_descriptor];
    let mut anchored_checkpoints = vec![header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .log_checkpoint
        .as_ref()
        .unwrap()
        .clone()];
    let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let selected_accounts = observer_assignments
        .iter()
        .map(|assignment| assignment.observer_account_id)
        .collect::<std::collections::HashSet<_>>();
    let mut selected_manifests = HashMap::new();
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
        let log_id = format!("observer-canonical-{}", hex::encode(account.as_ref()));
        let observer_manifest =
            build_observer_manifest(account, manifest.epoch, [81u8; 32], &log_id, &member_keys);
        if selected_accounts.contains(&account) {
            selected_manifests.insert(account, (observer_manifest.clone(), member_keys));
        }
        observer_manifests.push(observer_manifest);
    }

    let mut observer_transcripts = Vec::new();
    for assignment in observer_assignments {
        let (observer_manifest, member_keys) = selected_manifests
            .remove(&assignment.observer_account_id)
            .unwrap();
        let provisional = AsymptoteObserverCertificate {
            assignment: assignment.clone(),
            verdict: AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [0u8; 32],
            guardian_certificate: GuardianQuorumCertificate::default(),
        };
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
            counter: u64::from(assignment.round) + 1,
            trace_hash: [assignment.round as u8 + 11; 32],
            measurement_root: observer_manifest.measurement_profile_root,
            policy_hash: observer_manifest.policy_hash,
        };
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
            u64::from(assignment.round) + 50,
        ));
        anchored_checkpoints.push(
            observer_guardian_certificate
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
        );
        observer_descriptors.push(build_log_descriptor(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
        ));
        observer_transcripts.push(AsymptoteObserverTranscript {
            statement,
            guardian_certificate: observer_guardian_certificate,
        });
    }

    let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: manifest.epoch,
        height: header.height,
        view: header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: manifest.epoch,
        height: header.height,
        view: header.view,
        challenges_root,
        challenge_count: 0,
    };
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: manifest.epoch,
        height: header.height,
        view: header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 25_000,
    };

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
        observer_close_certificate: None,
        observer_transcripts: observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment.clone()),
        observer_challenge_commitment: Some(challenge_commitment.clone()),
        observer_canonical_close: Some(canonical_close.clone()),
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        header.sealed_finality_proof.as_mut().unwrap(),
        &guardian_log_keypair,
    );

    let mut parent_view = build_parent_view_with_asymptote_observers(
        &manifest,
        &observer_descriptors,
        policy,
        witness_seed,
        &anchored_checkpoints,
        validators,
        &observer_manifests,
    );
    parent_view.state.insert(
        guardian_registry_observer_transcript_commitment_key(
            manifest.epoch,
            header.height,
            header.view,
        ),
        codec::to_bytes_canonical(&transcript_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_challenge_commitment_key(
            manifest.epoch,
            header.height,
            header.view,
        ),
        codec::to_bytes_canonical(&challenge_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_canonical_close_key(manifest.epoch, header.height, header.view),
        codec::to_bytes_canonical(&canonical_close).unwrap(),
    );

    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_canonical_observer_sealed_finality_proof_without_registry_copies() {
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&fixture.observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: fixture.observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: 0,
    };
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: fixture.observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 30_000,
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
        observer_transcripts: fixture.observer_transcripts.clone(),
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
    fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_canonical_observer_sealed_finality_proof_with_mismatched_registry_copy()
{
    let mut fixture = build_canonical_observer_fixture();
    let base_certificate = fixture
        .header
        .guardian_certificate
        .as_ref()
        .unwrap()
        .clone();
    let observer_assignments_hash =
        canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
    let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&fixture.observer_transcripts).unwrap();
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
    let transcript_commitment = AsymptoteObserverTranscriptCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        transcript_count: fixture.observer_transcripts.len() as u16,
    };
    let challenge_commitment = AsymptoteObserverChallengeCommitment {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        challenges_root,
        challenge_count: 0,
    };
    let canonical_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: fixture.observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 31_000,
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
        observer_transcripts: fixture.observer_transcripts.clone(),
        observer_challenges: observer_challenges.clone(),
        observer_transcript_commitment: Some(transcript_commitment.clone()),
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

    let mut parent_view = canonical_observer_parent_view(&fixture);
    let mut mismatched_transcript_commitment = transcript_commitment;
    mismatched_transcript_commitment.transcripts_root = [0xabu8; 32];
    parent_view.state.insert(
        guardian_registry_observer_transcript_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&mismatched_transcript_commitment).unwrap(),
    );

    let err = fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("observer transcript commitment does not match the on-chain registry copy"));
}

#[tokio::test]
async fn asymptote_accepts_canonical_observer_abort_proof() {
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
        details: "observer transcript was omitted from the canonical surface".into(),
    };
    finalize_observer_challenge_id(&mut challenge);
    let observer_challenges = vec![challenge.clone()];
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
    let canonical_abort = AsymptoteObserverCanonicalAbort {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: observer_challenges.len() as u16,
        challenge_cutoff_timestamp_ms: 32_000,
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
        observer_transcript_commitment: Some(transcript_commitment.clone()),
        observer_challenge_commitment: Some(challenge_commitment.clone()),
        observer_canonical_close: None,
        observer_canonical_abort: Some(canonical_abort.clone()),
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let mut parent_view = canonical_observer_parent_view(&fixture);
    parent_view.state.insert(
        guardian_registry_observer_transcript_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&transcript_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_challenge_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&challenge_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_canonical_abort_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&canonical_abort).unwrap(),
    );

    fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_accepts_invalid_canonical_close_challenge_abort_proof() {
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
    let mut invalid_close = AsymptoteObserverCanonicalClose {
        epoch: fixture.manifest.epoch,
        height: fixture.header.height,
        view: fixture.header.view,
        assignments_hash: observer_assignments_hash,
        transcripts_root,
        challenges_root: empty_challenges_root,
        transcript_count: observer_transcripts.len() as u16,
        challenge_count: 0,
        challenge_cutoff_timestamp_ms: 34_000,
    };
    invalid_close.transcripts_root[0] ^= 0xFF;
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
        canonical_close: Some(invalid_close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(&invalid_close).unwrap(),
        details: "proof-carried canonical close does not match the transcript surface".into(),
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
        challenge_cutoff_timestamp_ms: 34_000,
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
        observer_transcript_commitment: Some(transcript_commitment.clone()),
        observer_challenge_commitment: Some(challenge_commitment.clone()),
        observer_canonical_close: None,
        observer_canonical_abort: Some(canonical_abort.clone()),
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    sign_test_sealed_finality_proof(
        fixture.header.sealed_finality_proof.as_mut().unwrap(),
        &fixture.guardian_log_keypair,
    );

    let mut parent_view = canonical_observer_parent_view(&fixture);
    parent_view.state.insert(
        guardian_registry_observer_transcript_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&transcript_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_challenge_commitment_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&challenge_commitment).unwrap(),
    );
    parent_view.state.insert(
        guardian_registry_observer_canonical_abort_key(
            fixture.manifest.epoch,
            fixture.header.height,
            fixture.header.view,
        ),
        codec::to_bytes_canonical(&canonical_abort).unwrap(),
    );

    fixture
        .engine
        .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
        .await
        .unwrap();
}

#[tokio::test]
async fn asymptote_rejects_missing_transcript_challenge_with_wrong_assignment_hash() {
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
        evidence_hash: [0xAAu8; 32],
        details: "observer transcript was omitted from the canonical surface".into(),
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
    assert!(err
        .to_string()
        .contains("missing-transcript challenge evidence hash does not match the assignment"));
}

