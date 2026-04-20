use super::*;
use crate::sign::bls::{verify_aggregate_fast, BlsKeyPair, BlsPublicKey, BlsSignature};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_types::app::{
    AccountId, GuardianCommitteeMember, GuardianDecisionDomain, GuardianWitnessCommitteeManifest,
    GuardianWitnessStatement, SignatureSuite,
};

fn test_manifest(member_keys: &[BlsKeyPair]) -> GuardianCommitteeManifest {
    GuardianCommitteeManifest {
        validator_account_id: AccountId([7u8; 32]),
        epoch: 3,
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
        measurement_profile_root: [11u8; 32],
        policy_hash: [9u8; 32],
        transparency_log_id: "guardian-test".into(),
    }
}

fn test_decision(counter: u64, trace_hash: [u8; 32]) -> GuardianDecision {
    GuardianDecision {
        domain: GuardianDecisionDomain::ConsensusSlot as u8,
        subject: vec![1, 2, 3],
        payload_hash: [5u8; 32],
        counter,
        trace_hash,
        measurement_root: [13u8; 32],
        policy_hash: [9u8; 32],
    }
}

fn test_witness_manifest(member_keys: &[BlsKeyPair]) -> GuardianWitnessCommitteeManifest {
    GuardianWitnessCommitteeManifest {
        committee_id: "witness-a".into(),
        stratum_id: "stratum-a".into(),
        epoch: 7,
        threshold: 2,
        members: member_keys
            .iter()
            .enumerate()
            .map(|(idx, keypair)| GuardianCommitteeMember {
                member_id: format!("witness-{idx}"),
                signature_suite: SignatureSuite::BLS12_381,
                public_key: keypair.public_key().to_bytes(),
                endpoint: None,
                provider: None,
                region: None,
                host_class: None,
                key_authority_kind: None,
            })
            .collect(),
        policy_hash: [19u8; 32],
        transparency_log_id: "witness-test".into(),
    }
}

fn test_witness_statement() -> GuardianWitnessStatement {
    GuardianWitnessStatement {
        producer_account_id: AccountId([9u8; 32]),
        height: 11,
        view: 4,
        guardian_manifest_hash: [21u8; 32],
        guardian_decision_hash: [22u8; 32],
        guardian_counter: 5,
        guardian_trace_hash: [23u8; 32],
        guardian_measurement_root: [24u8; 32],
        guardian_checkpoint_root: [25u8; 32],
        recovery_binding: None,
    }
}

#[test]
fn quorum_certificate_verifies() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let manifest = test_manifest(&member_keys);
    let decision = test_decision(1, [17u8; 32]);
    let certificate = sign_decision_with_members(
        &manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &[
            (0, member_keys[0].private_key()),
            (1, member_keys[1].private_key()),
        ],
    )
    .unwrap();

    verify_quorum_certificate(&manifest, &decision, &certificate).unwrap();
}

#[test]
fn bitfield_rejects_duplicates() {
    let err = encode_signers_bitfield(4, &[0, 0]).unwrap_err();
    assert!(matches!(err, CryptoError::InvalidInput(_)));
}

#[test]
fn witness_certificate_verifies() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let manifest = test_witness_manifest(&member_keys);
    let statement = test_witness_statement();
    let certificate = sign_witness_statement_with_members(
        &manifest,
        &statement,
        &[
            (0, member_keys[0].private_key()),
            (2, member_keys[2].private_key()),
        ],
    )
    .unwrap();

    verify_witness_certificate(&manifest, &statement, &certificate).unwrap();
}

#[test]
fn witness_certificate_rejects_recovery_binding_mismatch() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let manifest = test_witness_manifest(&member_keys);
    let mut statement = test_witness_statement();
    statement.recovery_binding = Some(ioi_types::app::GuardianWitnessRecoveryBinding {
        recovery_capsule_hash: [41u8; 32],
        share_commitment_hash: [42u8; 32],
    });
    let mut certificate = sign_witness_statement_with_members(
        &manifest,
        &statement,
        &[
            (0, member_keys[0].private_key()),
            (2, member_keys[2].private_key()),
        ],
    )
    .unwrap();
    certificate.recovery_binding = None;

    let err = verify_witness_certificate(&manifest, &statement, &certificate).unwrap_err();
    assert!(matches!(err, CryptoError::InvalidInput(_)));
}

#[test]
fn committee_manifest_hash_ignores_endpoints() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let mut without_endpoints = test_manifest(&member_keys);
    let mut with_endpoints = without_endpoints.clone();
    with_endpoints.members[0].endpoint = Some("http://127.0.0.1:23004".into());
    with_endpoints.members[1].endpoint = Some("http://127.0.0.1:23104".into());

    assert_eq!(
        canonical_manifest_hash(&without_endpoints).unwrap(),
        canonical_manifest_hash(&with_endpoints).unwrap()
    );
}

#[test]
fn witness_manifest_hash_ignores_endpoints() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let mut without_endpoints = test_witness_manifest(&member_keys);
    let mut with_endpoints = without_endpoints.clone();
    with_endpoints.members[0].endpoint = Some("http://127.0.0.1:33004".into());
    with_endpoints.members[1].endpoint = Some("http://127.0.0.1:33104".into());

    assert_eq!(
        canonical_witness_manifest_hash(&without_endpoints).unwrap(),
        canonical_witness_manifest_hash(&with_endpoints).unwrap()
    );
}

fn reference_decode_signers_bitfield(
    committee_len: usize,
    signers_bitfield: &[u8],
) -> Result<Vec<usize>, CryptoError> {
    let expected_len = committee_len.div_ceil(8);
    if signers_bitfield.len() != expected_len {
        return Err(CryptoError::InvalidInput(
            "invalid signer bitfield length".into(),
        ));
    }

    let mut indexes = Vec::new();
    for index in 0..committee_len {
        let byte = signers_bitfield[index / 8];
        if ((byte >> (index % 8)) & 1) == 1 {
            indexes.push(index);
        }
    }

    for padding_index in committee_len..(expected_len * 8) {
        let byte = signers_bitfield[padding_index / 8];
        if ((byte >> (padding_index % 8)) & 1) == 1 {
            return Err(CryptoError::InvalidInput(
                "signer bitfield has non-zero padding bits".into(),
            ));
        }
    }

    Ok(indexes)
}

fn reference_verify_quorum_certificate(
    manifest: &GuardianCommitteeManifest,
    decision: &GuardianDecision,
    certificate: &GuardianQuorumCertificate,
) -> Result<(), CryptoError> {
    if certificate.manifest_hash != canonical_manifest_hash(manifest)? {
        return Err(CryptoError::InvalidInput(
            "guardian certificate manifest hash mismatch".into(),
        ));
    }
    if certificate.epoch != manifest.epoch {
        return Err(CryptoError::InvalidInput(
            "guardian certificate epoch mismatch".into(),
        ));
    }
    if certificate.decision_hash != canonical_decision_hash(decision)? {
        return Err(CryptoError::InvalidInput(
            "guardian certificate decision hash mismatch".into(),
        ));
    }
    if certificate.measurement_root != decision.measurement_root {
        return Err(CryptoError::InvalidInput(
            "guardian certificate measurement root mismatch".into(),
        ));
    }

    let signer_indexes =
        reference_decode_signers_bitfield(manifest.members.len(), &certificate.signers_bitfield)?;
    if signer_indexes.len() < usize::from(manifest.threshold) {
        return Err(CryptoError::InvalidInput(
            "guardian certificate threshold not met".into(),
        ));
    }

    let public_keys = signer_indexes
        .into_iter()
        .map(|index| {
            manifest
                .members
                .get(index)
                .ok_or_else(|| {
                    CryptoError::InvalidInput(
                        "guardian certificate signer outside committee".into(),
                    )
                })
                .and_then(|member| BlsPublicKey::from_bytes(&member.public_key))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let signature = BlsSignature::from_bytes(&certificate.aggregated_signature)?;
    if !verify_aggregate_fast(&public_keys, &certificate.decision_hash, &signature)? {
        return Err(CryptoError::VerificationFailed);
    }
    Ok(())
}

fn reference_verify_witness_certificate(
    manifest: &GuardianWitnessCommitteeManifest,
    statement: &GuardianWitnessStatement,
    certificate: &GuardianWitnessCertificate,
) -> Result<(), CryptoError> {
    if certificate.manifest_hash != canonical_witness_manifest_hash(manifest)? {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate manifest hash mismatch".into(),
        ));
    }
    if certificate.epoch != manifest.epoch {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate epoch mismatch".into(),
        ));
    }
    if certificate.recovery_binding != statement.recovery_binding {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate recovery binding mismatch".into(),
        ));
    }
    if certificate.statement_hash != canonical_witness_statement_hash(statement)? {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate statement hash mismatch".into(),
        ));
    }

    let signer_indexes =
        reference_decode_signers_bitfield(manifest.members.len(), &certificate.signers_bitfield)?;
    if signer_indexes.len() < usize::from(manifest.threshold) {
        return Err(CryptoError::InvalidInput(
            "guardian witness certificate threshold not met".into(),
        ));
    }

    let public_keys = signer_indexes
        .into_iter()
        .map(|index| {
            manifest
                .members
                .get(index)
                .ok_or_else(|| {
                    CryptoError::InvalidInput(
                        "guardian witness certificate signer outside committee".into(),
                    )
                })
                .and_then(|member| BlsPublicKey::from_bytes(&member.public_key))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let signature = BlsSignature::from_bytes(&certificate.aggregated_signature)?;
    if !verify_aggregate_fast(&public_keys, &certificate.statement_hash, &signature)? {
        return Err(CryptoError::VerificationFailed);
    }
    Ok(())
}

#[test]
fn quorum_certificate_matches_reference_verifier() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let manifest = test_manifest(&member_keys);
    let decision = test_decision(7, [31u8; 32]);
    let certificate = sign_decision_with_members(
        &manifest,
        &decision,
        decision.counter,
        decision.trace_hash,
        &[
            (0, member_keys[0].private_key()),
            (1, member_keys[1].private_key()),
        ],
    )
    .unwrap();

    let mut cases = Vec::new();
    cases.push(certificate.clone());

    let mut wrong_manifest = certificate.clone();
    wrong_manifest.manifest_hash[0] ^= 0x55;
    cases.push(wrong_manifest);

    let mut wrong_epoch = certificate.clone();
    wrong_epoch.epoch += 1;
    cases.push(wrong_epoch);

    let mut wrong_decision = certificate.clone();
    wrong_decision.decision_hash[1] ^= 0x11;
    cases.push(wrong_decision);

    let mut wrong_measurement = certificate.clone();
    wrong_measurement.measurement_root[2] ^= 0x22;
    cases.push(wrong_measurement);

    let mut insufficient_threshold = certificate.clone();
    insufficient_threshold.signers_bitfield = encode_signers_bitfield(3, &[0]).unwrap();
    cases.push(insufficient_threshold);

    let mut invalid_padding = certificate.clone();
    invalid_padding.signers_bitfield = vec![0b1000_0011];
    cases.push(invalid_padding);

    let mut bad_signature = certificate.clone();
    bad_signature.aggregated_signature[0] ^= 0x80;
    cases.push(bad_signature);

    for case in cases {
        let actual = verify_quorum_certificate(&manifest, &decision, &case).is_ok();
        let reference = reference_verify_quorum_certificate(&manifest, &decision, &case).is_ok();
        assert_eq!(
            actual, reference,
            "guardian quorum verifier drifted from reference model"
        );
    }
}

#[test]
fn witness_certificate_matches_reference_verifier() {
    let member_keys = vec![
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
        BlsKeyPair::generate().unwrap(),
    ];
    let manifest = test_witness_manifest(&member_keys);
    let statement = test_witness_statement();
    let certificate = sign_witness_statement_with_members(
        &manifest,
        &statement,
        &[
            (0, member_keys[0].private_key()),
            (2, member_keys[2].private_key()),
        ],
    )
    .unwrap();

    let mut cases = Vec::new();
    cases.push(certificate.clone());

    let mut wrong_manifest = certificate.clone();
    wrong_manifest.manifest_hash[0] ^= 0x21;
    cases.push(wrong_manifest);

    let mut wrong_epoch = certificate.clone();
    wrong_epoch.epoch += 1;
    cases.push(wrong_epoch);

    let mut wrong_statement = certificate.clone();
    wrong_statement.statement_hash[1] ^= 0x33;
    cases.push(wrong_statement);

    let mut insufficient_threshold = certificate.clone();
    insufficient_threshold.signers_bitfield = encode_signers_bitfield(3, &[2]).unwrap();
    cases.push(insufficient_threshold);

    let mut invalid_padding = certificate.clone();
    invalid_padding.signers_bitfield = vec![0b1000_0101];
    cases.push(invalid_padding);

    let mut bad_signature = certificate.clone();
    bad_signature.aggregated_signature[0] ^= 0x40;
    cases.push(bad_signature);

    let mut wrong_recovery_binding = certificate.clone();
    wrong_recovery_binding.recovery_binding =
        Some(ioi_types::app::GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: [90u8; 32],
            share_commitment_hash: [91u8; 32],
        });
    cases.push(wrong_recovery_binding);

    for case in cases {
        let actual = verify_witness_certificate(&manifest, &statement, &case).is_ok();
        let reference = reference_verify_witness_certificate(&manifest, &statement, &case).is_ok();
        assert_eq!(
            actual, reference,
            "guardian witness verifier drifted from reference model"
        );
    }
}
