#[test]
fn rejects_invalid_aggregate_signature() {
    let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .aggregated_signature[0] ^= 0x01;
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn rejects_signer_outside_committee() {
    let (engine, mut header, mut manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    manifest.members.truncate(2);
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .signers_bitfield = encode_signers_bitfield(3, &[0, 2]).unwrap();
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn rejects_insufficient_threshold() {
    let (_, header, manifest, preimage, member_keys, _) = build_case(&[(0, 0), (1, 1)]);
    let payload_hash = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap();
    let decision = GuardianDecision {
        domain: GuardianDecisionDomain::ConsensusSlot as u8,
        subject: manifest.validator_account_id.0.to_vec(),
        payload_hash,
        counter: header.oracle_counter,
        trace_hash: header.oracle_trace_hash,
        measurement_root: manifest.measurement_profile_root,
        policy_hash: manifest.policy_hash,
    };
    let err = sign_decision_with_members(
        &manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &[(0, member_keys[0].private_key())],
    )
    .unwrap_err();
    assert!(err.to_string().contains("insufficient local signers"));
}

#[test]
fn rejects_wrong_decision_hash() {
    let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    header.guardian_certificate.as_mut().unwrap().decision_hash[0] ^= 0x11;
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn rejects_wrong_epoch() {
    let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    header.guardian_certificate.as_mut().unwrap().epoch += 1;
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn rejects_wrong_manifest_hash() {
    let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    header.guardian_certificate.as_mut().unwrap().manifest_hash[0] ^= 0x55;
    let err = engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[test]
fn duplicate_signer_indexes_are_rejected_before_certificate_construction() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let manifest = GuardianCommitteeManifest {
        validator_account_id: AccountId([8u8; 32]),
        epoch: 1,
        threshold: 2,
        members: member_keys
            .iter()
            .enumerate()
            .map(|(idx, keypair)| GuardianCommitteeMember {
                member_id: format!("member-{idx}"),
                signature_suite: SignatureSuite::BLS12_381,
                public_key: keypair.public_key().to_bytes(),
                endpoint: None,
                provider: None,
                region: None,
                host_class: None,
                key_authority_kind: None,
            })
            .collect(),
        measurement_profile_root: [12u8; 32],
        policy_hash: [13u8; 32],
        transparency_log_id: "guardian-test".into(),
    };
    let decision = GuardianDecision {
        domain: GuardianDecisionDomain::ConsensusSlot as u8,
        subject: manifest.validator_account_id.0.to_vec(),
        payload_hash: [99u8; 32],
        counter: 1,
        trace_hash: [77u8; 32],
        measurement_root: manifest.measurement_profile_root,
        policy_hash: manifest.policy_hash,
    };
    let err = sign_decision_with_members(
        &manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &[
            (0, member_keys[0].private_key()),
            (0, member_keys[0].private_key()),
        ],
    )
    .unwrap_err();
    assert!(err.to_string().contains("duplicate signer index"));
}

#[test]
fn experimental_nested_guardian_requires_witness_certificate() {
    let (mut engine, header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let witness_members = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest = build_witness_manifest(&witness_members);
    let err = engine
        .verify_experimental_witness_certificate_against_manifest(
            &header,
            header.guardian_certificate.as_ref().unwrap(),
            &witness_manifest,
        )
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap();
}

#[test]
fn experimental_nested_guardian_verifies_witness_certificate() {
    let (mut engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let witness_members = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest = build_witness_manifest(&witness_members);
    let guardian_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let statement = engine.experimental_witness_statement(&header, &guardian_certificate);
    let witness_certificate = sign_witness_statement_with_members(
        &witness_manifest,
        &statement,
        &[
            (0, witness_members[0].private_key()),
            (2, witness_members[2].private_key()),
        ],
    )
    .unwrap();
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .experimental_witness_certificate = Some(witness_certificate);

    engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap();
    engine
        .verify_experimental_witness_certificate_against_manifest(
            &header,
            header.guardian_certificate.as_ref().unwrap(),
            &witness_manifest,
        )
        .unwrap();
}

#[test]
fn experimental_nested_guardian_rejects_tampered_recovery_binding() {
    let (mut engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
    let witness_members = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let witness_manifest = build_witness_manifest(&witness_members);
    let guardian_certificate = header.guardian_certificate.as_ref().unwrap().clone();
    let mut statement = engine.experimental_witness_statement(&header, &guardian_certificate);
    statement.recovery_binding = Some(GuardianWitnessRecoveryBinding {
        recovery_capsule_hash: [61u8; 32],
        share_commitment_hash: [62u8; 32],
    });
    let mut witness_certificate = sign_witness_statement_with_members(
        &witness_manifest,
        &statement,
        &[
            (0, witness_members[0].private_key()),
            (2, witness_members[2].private_key()),
        ],
    )
    .unwrap();
    witness_certificate.recovery_binding = Some(GuardianWitnessRecoveryBinding {
        recovery_capsule_hash: [63u8; 32],
        share_commitment_hash: [64u8; 32],
    });
    header
        .guardian_certificate
        .as_mut()
        .unwrap()
        .experimental_witness_certificate = Some(witness_certificate);

    engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap();
    let err = engine
        .verify_experimental_witness_certificate_against_manifest(
            &header,
            header.guardian_certificate.as_ref().unwrap(),
            &witness_manifest,
        )
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn experimental_nested_guardian_rejects_unassigned_witness_certificate() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
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
        max_reassignment_depth: 1,
    };
    let expected_assignment = derive_guardian_witness_assignment(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
    )
    .unwrap();
    let wrong_manifest = if expected_assignment.manifest_hash == witness_hash_a {
        &witness_manifest_b
    } else {
        &witness_manifest_a
    };
    let wrong_members = if expected_assignment.manifest_hash == witness_hash_a {
        &witness_members_b
    } else {
        &witness_members_a
    };
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
    let mut witness_certificate = sign_witness_statement_with_members(
        wrong_manifest,
        &statement,
        &[
            (0, wrong_members[0].private_key()),
            (1, wrong_members[1].private_key()),
            (2, wrong_members[2].private_key()),
        ],
    )
    .unwrap();
    let witness_checkpoint_entry =
        codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
    witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
        &wrong_manifest.transparency_log_id,
        &witness_log_keypair,
        &[witness_checkpoint_entry],
        0,
        1,
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
        &[header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone()],
    );
    let err = engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap_err();
    assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
}

#[tokio::test]
async fn experimental_nested_guardian_accepts_deterministically_assigned_witness_certificate() {
    let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
        build_case(&[(0, 0), (1, 1)]);
    engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
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

    let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
    let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
    let witness_set = GuardianWitnessSet {
        epoch: witness_manifest_a.epoch,
        manifest_hashes: vec![witness_hash_a, witness_hash_b],
        checkpoint_interval_blocks: 1,
    };
    let witness_seed = GuardianWitnessEpochSeed {
        epoch: witness_manifest_a.epoch,
        seed: [99u8; 32],
        checkpoint_interval_blocks: 1,
        max_reassignment_depth: 1,
    };
    let expected_assignment = derive_guardian_witness_assignment(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
    )
    .unwrap();
    let (assigned_manifest, assigned_members) =
        if expected_assignment.manifest_hash == witness_hash_a {
            (&witness_manifest_a, &witness_members_a)
        } else {
            (&witness_manifest_b, &witness_members_b)
        };
    let statement = engine
        .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
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
        &[witness_checkpoint_entry],
        0,
        1,
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
        &[
            header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
            header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .experimental_witness_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
        ],
    );
    engine
        .verify_guardianized_certificate(&header, &preimage, &parent_view)
        .await
        .unwrap();
}

