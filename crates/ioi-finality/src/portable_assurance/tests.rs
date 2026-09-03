use super::*;
use ioi_crypto::transport::pq_authenticated_channel::{
    accept_pq_channel, attest_pq_channel_completion, complete_pq_channel, finish_pq_channel,
    start_pq_channel, PqChannelScopeV1,
};
use ioi_types::app::{
    CollateralBondV1, EconomicAssuranceVersionV1, EffectFenceV1, EffectManifestVersionV1,
    EffectResourceKeyV1, ExternalResourceContractV1, ExternalResourceProfileV1,
    ReconciliationPolicyV1, SealKeyBindingV1, SealKeyManifestEntryV1, SealKeyScopeV1,
    SlashableBehaviorV1, SlashableCollateralRequirementV1, AFT_SEAL_KEY_MANIFEST_SCHEMA_V1,
    AFT_SEAL_PROTOCOL_VERSION_V2, AFT_SEAL_SHARE_SCHEMA_V2,
};
use slh_dsa::signature::Signer;
use slh_dsa::{Sha2_128s, SigningKey as SlhDsaSigningKey};
use std::collections::BTreeSet;
use std::sync::OnceLock;

fn hash<T: Serialize>(domain: &[u8], value: &T) -> [u8; 32] {
    let bytes = serde_jcs::to_vec(value).unwrap();
    let mut material = domain.to_vec();
    material.extend(bytes);
    Sha256::digest(material).into()
}

fn channel_coverage(
    context: &FinalityPqContext,
    member_keys: &[(AccountId, MldsaKeyPair)],
    finality_hash: [u8; 32],
) -> PortablePqChannelCoverageV1 {
    let mut sessions = Vec::new();
    for initiator_index in 0..member_keys.len() {
        for responder_index in (initiator_index + 1)..member_keys.len() {
            let (initiator_id, initiator) = &member_keys[initiator_index];
            let (responder_id, responder) = &member_keys[responder_index];
            let scope = PqChannelScopeV1 {
                network_id: context.network_id,
                configuration_hash: context.configuration_hash,
                epoch: context.epoch,
                initiator: *initiator_id,
                responder: *responder_id,
                initiator_transport_binding: hash(b"m8-carrier", &initiator_index),
                responder_transport_binding: hash(b"m8-carrier", &responder_index),
            };
            let responder_hash = account_id_from_key_material(
                SignatureSuite::ML_DSA_44,
                &responder.public_key().to_bytes(),
            )
            .unwrap();
            let initiator_hash = account_id_from_key_material(
                SignatureSuite::ML_DSA_44,
                &initiator.public_key().to_bytes(),
            )
            .unwrap();
            let (initiator_state, hello) =
                start_pq_channel(scope.clone(), initiator, responder_hash).unwrap();
            let (responder_state, server) = accept_pq_channel(
                &scope,
                initiator_hash,
                responder_hash,
                responder,
                hello.clone(),
            )
            .unwrap();
            let (finish, initiator_keys) =
                finish_pq_channel(initiator_state, server.clone()).unwrap();
            let responder_keys = complete_pq_channel(responder_state, finish.clone()).unwrap();
            sessions.push(
                attest_pq_channel_completion(
                    hello,
                    server,
                    finish,
                    &initiator_keys,
                    &responder_keys,
                    initiator,
                    responder,
                    finality_hash,
                )
                .unwrap(),
            );
        }
    }
    PortablePqChannelCoverageV1 {
        schema_version: PORTABLE_PQ_CHANNEL_COVERAGE_V1.into(),
        network_id: context.network_id,
        configuration_hash: context.configuration_hash,
        epoch: context.epoch,
        protected_finality_hash: finality_hash,
        sessions,
    }
}

fn terminal_seal(
    context: &FinalityPqContext,
    member_keys: &[(AccountId, MldsaKeyPair)],
    conflict_domain: [u8; 32],
    seal_root: [u8; 32],
) -> PortableTerminalSealV1 {
    let mut signing_keys = Vec::new();
    let mut entries = Vec::new();
    for (index, (member_id, _)) in member_keys.iter().enumerate() {
        let signing_key = SlhDsaSigningKey::<Sha2_128s>::slh_keygen_internal(
            &[index as u8 + 1; 16],
            &[index as u8 + 11; 16],
            &[index as u8 + 21; 16],
        );
        let initial_key = SealKeyBindingV1 {
            scope: SealKeyScopeV1 {
                network_id: context.network_id,
                configuration_id: context.configuration_hash,
                epoch: context.epoch,
                conflict_domain_id: conflict_domain,
                member_id: *member_id,
                member_index: index as u32,
            },
            key_index: 0,
            signature_suite: SignatureSuite::SLH_DSA_SHA2_128S,
            public_key: signing_key.as_ref().to_vec(),
            predecessor_key_commitment: [index as u8 + 31; 32],
        };
        entries.push(SealKeyManifestEntryV1 {
            initial_key_commitment: initial_key.commitment().unwrap(),
            initial_key,
        });
        signing_keys.push(signing_key);
    }
    let key_manifest = SealKeyManifestV1 {
        schema_version: AFT_SEAL_KEY_MANIFEST_SCHEMA_V1,
        entries,
    };
    key_manifest.validate().unwrap();
    let shares = key_manifest
        .entries
        .iter()
        .zip(&signing_keys)
        .enumerate()
        .map(|(index, (entry, signing_key))| {
            let mut share = SealShareV2 {
                protocol_version: AFT_SEAL_PROTOCOL_VERSION_V2,
                schema_version: AFT_SEAL_SHARE_SCHEMA_V2,
                current_key: entry.initial_key.clone(),
                seal_slot: 0,
                seal_root,
                next_key_commitment: [index as u8 + 71; 32],
                signature: Vec::new(),
            };
            share.signature = signing_key
                .try_sign(&share.signing_bytes().unwrap())
                .unwrap()
                .to_vec();
            share
        })
        .collect();
    PortableTerminalSealV1 {
        schema_version: PORTABLE_TERMINAL_SEAL_V1.into(),
        key_manifest,
        shares,
    }
}

fn fixture() -> PortableAssuranceReceiptV1 {
    static FIXTURE: OnceLock<PortableAssuranceReceiptV1> = OnceLock::new();
    FIXTURE.get_or_init(build_fixture).clone()
}

fn trust_for(receipt: &PortableAssuranceReceiptV1) -> PortableAssuranceTrustV1 {
    PortableAssuranceTrustV1 {
        schema_version: PORTABLE_ASSURANCE_TRUST_V1.into(),
        network_id: receipt.configuration_snapshot.network_id,
        configuration_hash: receipt.configuration_snapshot.configuration_hash,
        epoch: receipt.configuration_snapshot.epoch,
        terminal_key_root: receipt.configuration_snapshot.key_root,
        allowed_receipt_public_keys_base64: BTreeSet::from([receipt
            .signature
            .public_key_base64
            .clone()]),
        required_anchors: receipt.requested_anchors.clone(),
        required_guarantees: receipt.policy.clone(),
    }
}

fn build_fixture() -> PortableAssuranceReceiptV1 {
    let (finality_bundle, member_keys) = crate::tests::runtime_v3_hash_async_pq_bundle_with_keys();
    let finality = match verify_portable_bundle(&finality_bundle).unwrap() {
        VerifiedPortableClaim::RuntimeV3(claim) => claim,
        _ => unreachable!(),
    };
    let configuration_hash = finality.assurance.safety.configuration_hash.unwrap();
    let finality_context = finality_pq_context(&finality_bundle).unwrap();
    let finality_hash = decode_hash(&hash_json(&finality_bundle).unwrap()).unwrap();
    let endpoint = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    let endpoint_key_hash =
        account_id_from_key_material(SignatureSuite::ML_DSA_44, &endpoint.public_key().to_bytes())
            .unwrap();
    let profile = ExternalResourceProfileV1 {
        adapter_id: "adapter://test/atomic".into(),
        adapter_version: "v1".into(),
        resource_profile_id: "resource-profile://test/atomic".into(),
        contract: ExternalResourceContractV1::AtomicPutIfAbsent,
        externalization_pq: true,
        endpoint_pq_key_hash: Some(endpoint_key_hash),
    };
    let conflict_domain_id = "domain://acme/runtime/hash-async";
    let conflict_domain_hash =
        ioi_types::app::conflict_domain_id_commitment(conflict_domain_id).unwrap();
    let policy = GuaranteeRequirementsV1 {
        minimum_finality_rank: Some(GuaranteeRank::SealedAllButOne),
        configuration_hash: Some(configuration_hash),
        conflict_domain_hash: Some(conflict_domain_hash),
        require_consensus_pq: true,
        require_channel_pq: true,
        require_externalization_pq: true,
        require_end_to_end_pq: true,
        require_no_private_threshold_setup: true,
        minimum_accountability: Some(AccountabilityV1::FullConfiguration),
        require_publication_retrievable: true,
        minimum_externalization: Some(ioi_types::app::ExternalizationModeV1::IdempotencyRegister),
        require_at_most_once: true,
        ..Default::default()
    };
    let manifest = EffectManifestV1 {
        schema_version: EffectManifestVersionV1::V1,
        effect_id: "effect://portable/1".into(),
        resource_id: "resource://portable/register".into(),
        conflict_domain_id: conflict_domain_id.into(),
        read_set: vec![EffectResourceKeyV1 {
            key: "balance/source".into(),
            predecessor: Some([21; 32]),
        }],
        write_set: vec![EffectResourceKeyV1 {
            key: "transfer/1".into(),
            predecessor: None,
        }],
        idempotency_key: "portable-transfer-1".into(),
        request_root: [22; 32],
        predecessor_root: [23; 32],
        intent_root: [24; 32],
        expected_outcome_root: [25; 32],
        resource_profile: profile,
        required_guarantees: policy.clone(),
        fence: EffectFenceV1::ProtocolHeight {
            configuration_hash,
            minimum_height: 1,
            maximum_height: 1000,
        },
        reconciliation: ReconciliationPolicyV1::LookupByIdempotencyKey {
            maximum_observations: 3,
        },
        irreversible: true,
    };
    let resource_record = ExternalResourceRecordV1 {
        resource_id: manifest.resource_id.clone(),
        idempotency_key: manifest.idempotency_key.clone(),
        request_root: manifest.request_root,
        predecessor_root: manifest.predecessor_root,
        outcome_root: manifest.expected_outcome_root,
        mutation_sequence: 1,
        evidence: Some(vec![1, 2, 3]),
        evidence_hash: Some(hash(
            b"ioi::aft::external-resource-evidence::v1\0",
            &vec![1, 2, 3],
        )),
    };
    let mut consequence = PortableConsequenceEvidenceV1 {
        manifest_root: manifest.commitment().unwrap(),
        intent_root: manifest.intent_root,
        execution_root: [26; 32],
        outcome_root: manifest.expected_outcome_root,
        reconciliation_root: [27; 32],
        resource_record,
        externalization_evidence: PortableExternalizationEvidenceV1 {
            schema_version: String::new(),
            algorithm: String::new(),
            endpoint_public_key_base64: String::new(),
            signature_base64: String::new(),
        },
    };
    sign_portable_externalization_evidence(&manifest, &mut consequence, &endpoint).unwrap();
    let channel_coverage = channel_coverage(&finality_context, &member_keys, finality_hash);
    let seal_root =
        terminal_seal_root(finality_hash, manifest.commitment().unwrap(), &consequence).unwrap();
    let terminal_seal = terminal_seal(
        &finality_context,
        &member_keys,
        conflict_domain_hash,
        seal_root,
    );
    let mut configuration_snapshot = PortableConfigurationSnapshotV1 {
        network_id: finality_context.network_id,
        configuration_hash,
        epoch: finality_context.epoch,
        key_root: terminal_seal.key_manifest.commitment().unwrap(),
        snapshot_height: 100,
        key_root_votes: Vec::new(),
    };
    sign_portable_configuration_snapshot(&mut configuration_snapshot, &member_keys).unwrap();
    let accountable = AccountabilityEvidenceV1 {
        schema_version: EconomicAssuranceVersionV1::V1,
        configuration_hash,
        behavior: SlashableBehaviorV1::ConflictingSignedStatements,
        evidence_predicate_hash: [28; 32],
        evidence_hash: [29; 32],
        implicated_members: BTreeSet::from([[30; 32]]),
        challenge_horizon_end: 200,
    };
    let bond = CollateralBondV1 {
        bond_id: [31; 32],
        collateral_id: [32; 32],
        owner_member_hash: [30; 32],
        asset_id_hash: [33; 32],
        amount_base_units: "100000000000000000000".into(),
        exclusive_configuration_hash: configuration_hash,
        locked_from: 1,
        locked_until: 250,
        challenge_horizon_end: 200,
        evidence_predicate_hash: [28; 32],
        slashing_contract_hash: [34; 32],
        active_encumbrance_hashes: BTreeSet::new(),
        withdrawal_pending: false,
    };
    let snapshot = BondSnapshotV1 {
        schema_version: EconomicAssuranceVersionV1::V1,
        snapshot_height: 100,
        configuration_hash,
        bonds: vec![bond],
    };
    let economic_claim = EconomicAssuranceV1 {
        schema_version: EconomicAssuranceVersionV1::V1,
        asset_id_hash: [33; 32],
        amount_base_units: "100000000000000000000".into(),
        configuration_hash,
        collateral_set_hash: hash(ioi_types::app::COLLATERAL_SET_V1_DOMAIN, &vec![[32; 32]]),
        bond_snapshot_root: snapshot.commitment().unwrap(),
        snapshot_height: 100,
        locked_until: 250,
        challenge_horizon_end: 200,
        evidence_predicate: SlashableBehaviorV1::ConflictingSignedStatements,
        evidence_predicate_hash: [28; 32],
        slashing_contract_hash: [34; 32],
        valuation_assumptions: None,
    };
    let economic =
        EconomicAssuranceVerifierV1::verify(&accountable, &snapshot, &economic_claim).unwrap();

    let consequence_hash = hash_serializable(&consequence).unwrap();
    let mut achieved = finality.assurance;
    let channel_hash = decode_hash(&hash_serializable(&channel_coverage).unwrap()).unwrap();
    achieved.crypto.channel_pq = true;
    achieved.constituent_hashes.insert(channel_hash);
    achieved.theorem_ids.insert("T12".into());
    achieved.externalization = manifest
        .resource_profile
        .advertised_externalization()
        .unwrap();
    achieved.crypto.externalization_pq = true;
    let seal_hash = decode_hash(&hash_serializable(&terminal_seal).unwrap()).unwrap();
    let n = member_keys.len() as u32;
    achieved.safety.model = SafetyModelV1::UnanimousAllButOne;
    achieved.safety.finality_rank = Some(GuaranteeRank::SealedAllButOne);
    achieved.safety.committee_n = Some(n);
    achieved.safety.fault_bound_f = Some(n - 1);
    achieved.safety.quorum_q = Some(n);
    achieved.accountability = AccountabilityV1::FullConfiguration;
    achieved
        .certificate_profiles
        .insert(CertificateProfile::PqUnanimousBoundaryClose);
    achieved
        .crypto
        .primitive_suites
        .insert(PrimitiveSuiteV1::HashBasedSignature);
    achieved
        .crypto
        .primitive_suites
        .remove(&PrimitiveSuiteV1::Unresolved);
    achieved.crypto.end_to_end_pq = true;
    achieved.constituent_hashes.insert(seal_hash);
    achieved.theorem_ids.extend(["T1".into(), "T7".into()]);
    achieved
        .constituent_hashes
        .insert(decode_hash(&consequence_hash).unwrap());
    achieved.theorem_ids.insert("T10".into());
    let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[achieved]).unwrap();
    let verified = economic.attach_to(&verified).unwrap();
    let trace = vec![
        PortableVerifiedTransformV1 {
            rule: GuaranteeTransformRuleV1::EstablishChannelPqFromTranscriptVerification,
            theorem_id: "T12".into(),
            evidence_hash: channel_hash,
        },
        PortableVerifiedTransformV1 {
            rule: GuaranteeTransformRuleV1::EstablishSafetyFromIndependentProof,
            theorem_id: "T1".into(),
            evidence_hash: seal_hash,
        },
        PortableVerifiedTransformV1 {
            rule: GuaranteeTransformRuleV1::EstablishExternalizationFromResourceProof,
            theorem_id: "T10".into(),
            evidence_hash: decode_hash(&consequence_hash).unwrap(),
        },
        PortableVerifiedTransformV1 {
            rule: GuaranteeTransformRuleV1::EstablishSlashableCollateralFromBondProof,
            theorem_id: "T11".into(),
            evidence_hash: economic.proof_commitment(),
        },
    ];
    PortableAssuranceReceiptV1 {
        schema_version: PORTABLE_ASSURANCE_RECEIPT_V1.into(),
        verifier_profile: PORTABLE_ASSURANCE_VERIFIER_V1.into(),
        finality_bundle,
        channel_coverage,
        terminal_seal,
        effect_manifest: manifest,
        policy,
        configuration_snapshot,
        consequence,
        economic_proof: Some(PortableEconomicProofV1 {
            evidence: accountable,
            snapshot,
            claimed: economic_claim,
        }),
        requested_anchors: vec![PortableAnchorV1 {
            anchor_ref: "anchor://test/1".into(),
            anchor_hash: [36; 32],
        }],
        claimed_achieved: verified.into_achieved(),
        transformation_trace: trace,
        receipt_hash: String::new(),
        signature: PortableReceiptSignatureV1 {
            algorithm: String::new(),
            public_key_base64: String::new(),
            signature_base64: String::new(),
        },
    }
}

#[test]
fn complete_receipt_verifies_from_canonical_bytes_without_runtime_state() {
    let mut receipt = fixture();
    let key = generate_portable_receipt_key().unwrap();
    let bytes = sign_portable_assurance_receipt(&mut receipt, &key).unwrap();
    let trust = trust_for(&receipt);
    let report = verify_portable_assurance_bytes(&bytes, &trust);
    assert!(report.accepted, "{:?}", report.refusal_reasons);
    assert!(report.policy_satisfied);
    assert_eq!(report.verified_transformations.len(), 4);
    assert!(report.verified_constituents.len() >= 7);
    let achieved = report.achieved_guarantee_vector.unwrap();
    assert!(achieved.crypto.channel_pq);
    assert!(achieved.crypto.externalization_pq);
    assert!(achieved.crypto.end_to_end_pq);
    assert_eq!(achieved.safety.model, SafetyModelV1::UnanimousAllButOne);

    // The release harness can export this fully verified, canonical receipt to
    // a temporary path for the separately maintained clean-room verifier. The
    // ordinary unit test writes nothing.
    if let Some(path) = std::env::var_os("AFT_PORTABLE_RECEIPT_OUTPUT") {
        std::fs::write(path, &bytes).expect("write requested portable receipt fixture");
    }
    if let Some(path) = std::env::var_os("AFT_PORTABLE_TRUST_OUTPUT") {
        std::fs::write(path, serde_jcs::to_vec(&trust).unwrap())
            .expect("write requested external trust fixture");
    }

    // Clean-room signature reproduction: RustCrypto imports the production
    // dcrypt output directly and verifies the exact receipt message.
    use ml_dsa::{MlDsa44, Signature as IndependentSignature, Verifier, VerifyingKey};
    let public_bytes = BASE64.decode(&receipt.signature.public_key_base64).unwrap();
    let signature_bytes = BASE64.decode(&receipt.signature.signature_base64).unwrap();
    let encoded =
        ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(public_bytes.as_slice()).unwrap();
    let public = VerifyingKey::<MlDsa44>::decode(&encoded);
    let signature = IndependentSignature::<MlDsa44>::try_from(signature_bytes.as_slice()).unwrap();
    public
        .verify(&signature_message(&receipt.receipt_hash), &signature)
        .expect("independent RustCrypto verifies production receipt signature");
}

#[test]
fn unknown_versions_algorithms_transforms_and_noncanonical_bytes_fail_closed() {
    let key = generate_portable_receipt_key().unwrap();
    for mutation in 0..3 {
        let mut receipt = fixture();
        match mutation {
            0 => receipt.schema_version = "ioi.aft.portable-assurance-receipt.v2".into(),
            1 => receipt.signature.algorithm = "unknown-pq".into(),
            2 => receipt.transformation_trace[0].theorem_id = "unknown".into(),
            _ => unreachable!(),
        }
        let bytes = sign_portable_assurance_receipt(&mut receipt, &key).unwrap();
        if mutation == 1 {
            // Signing normalizes the supported algorithm; mutate canonical bytes
            // and recompute neither signature nor hash.
            let mut value: Value = serde_json::from_slice(&bytes).unwrap();
            value["signature"]["algorithm"] = Value::String("unknown-pq".into());
            let bytes = serde_jcs::to_vec(&value).unwrap();
            let trust = trust_for(&receipt);
            assert!(!verify_portable_assurance_bytes(&bytes, &trust).accepted);
        } else {
            let trust = trust_for(&receipt);
            assert!(!verify_portable_assurance_bytes(&bytes, &trust).accepted);
        }
    }
    let mut receipt = fixture();
    let bytes = sign_portable_assurance_receipt(&mut receipt, &key).unwrap();
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&bytes).unwrap()).unwrap();
    let trust = trust_for(&receipt);
    assert!(!verify_portable_assurance_bytes(&pretty, &trust).accepted);
}

#[test]
fn mutations_of_every_major_constituent_are_rejected() {
    let key = generate_portable_receipt_key().unwrap();
    let mut receipt = fixture();
    let bytes = sign_portable_assurance_receipt(&mut receipt, &key).unwrap();
    let trust = trust_for(&receipt);
    for pointer in [
        "/effect_manifest/intent_root/0",
        "/configuration_snapshot/key_root/0",
        "/configuration_snapshot/key_root_votes/0/signature_base64",
        "/channel_coverage/sessions/0/protected_payload_hash/0",
        "/terminal_seal/shares/0/seal_root/0",
        "/consequence/outcome_root/0",
        "/consequence/externalization_evidence/signature_base64",
        "/economic_proof/snapshot/bonds/0/amount_base_units",
        "/claimed_achieved/crypto/consensus_pq",
        "/requested_anchors/0/anchor_hash/0",
        "/finality_bundle/checkpoint/finality_certificate/signature",
    ] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let slot = value.pointer_mut(pointer).unwrap();
        *slot = match slot {
            Value::Bool(value) => Value::Bool(!*value),
            Value::Number(value) => Value::from(value.as_u64().unwrap() ^ 1),
            Value::String(value) => Value::String(format!("{value}x")),
            _ => panic!("unsupported mutation slot"),
        };
        let mutated = serde_jcs::to_vec(&value).unwrap();
        assert!(
            !verify_portable_assurance_bytes(&mutated, &trust).accepted,
            "{pointer}"
        );
    }

    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    let encoded = value["signature"]["signature_base64"].as_str().unwrap();
    let mut signature = BASE64.decode(encoded).unwrap();
    signature[0] ^= 1;
    value["signature"]["signature_base64"] = Value::String(BASE64.encode(signature));
    let mutated = serde_jcs::to_vec(&value).unwrap();
    assert!(!verify_portable_assurance_bytes(&mutated, &trust).accepted);
}

#[test]
fn validly_reenveloped_inner_channel_seal_endpoint_and_enrollment_forgeries_refuse() {
    let envelope = generate_portable_receipt_key().unwrap();
    for mutation in 0..7 {
        let mut receipt = fixture();
        match mutation {
            0 => {
                receipt.channel_coverage.sessions.pop();
            }
            1 => receipt.channel_coverage.sessions[0].responder_attestation_signature[0] ^= 1,
            2 => receipt.terminal_seal.shares[0].signature[0] ^= 1,
            3 => {
                let encoded = &receipt.configuration_snapshot.key_root_votes[0].signature_base64;
                let mut signature = BASE64.decode(encoded).unwrap();
                signature[0] ^= 1;
                receipt.configuration_snapshot.key_root_votes[0].signature_base64 =
                    BASE64.encode(signature);
            }
            4 => {
                let encoded = &receipt
                    .consequence
                    .externalization_evidence
                    .signature_base64;
                let mut signature = BASE64.decode(encoded).unwrap();
                signature[0] ^= 1;
                receipt
                    .consequence
                    .externalization_evidence
                    .signature_base64 = BASE64.encode(signature);
            }
            5 => {
                receipt.terminal_seal.shares[0]
                    .current_key
                    .scope
                    .conflict_domain_id[0] ^= 1
            }
            6 => {
                receipt.terminal_seal.shares.pop();
            }
            _ => unreachable!(),
        }
        let bytes = sign_portable_assurance_receipt(&mut receipt, &envelope).unwrap();
        let trust = trust_for(&receipt);
        if let Some(directory) = std::env::var_os("AFT_PORTABLE_NEGATIVE_OUTPUT_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory)
                .expect("create requested portable negative fixture directory");
            let path = directory.join(format!(
                "validly-reenveloped-inner-mutation-{mutation}.json"
            ));
            std::fs::write(path, &bytes).expect("write requested portable negative fixture");
            let trust_path = directory.join(format!(
                "validly-reenveloped-inner-mutation-{mutation}.trust.json"
            ));
            std::fs::write(trust_path, serde_jcs::to_vec(&trust).unwrap())
                .expect("write requested portable negative trust fixture");
        }
        let report = verify_portable_assurance_bytes(&bytes, &trust);
        assert!(!report.accepted, "inner mutation {mutation} passed");
    }
}

#[test]
fn self_nominated_signer_roots_and_policy_are_not_authority() {
    let key = generate_portable_receipt_key().unwrap();
    let mut receipt = fixture();
    let bytes = sign_portable_assurance_receipt(&mut receipt, &key).unwrap();
    let trusted = trust_for(&receipt);

    let attacker_key = generate_portable_receipt_key().unwrap();
    let mut parallel = fixture();
    parallel.requested_anchors[0].anchor_hash[0] ^= 1;
    let parallel_bytes = sign_portable_assurance_receipt(&mut parallel, &attacker_key).unwrap();
    let report = verify_portable_assurance_bytes(&parallel_bytes, &trusted);
    assert!(!report.accepted);
    assert!(report
        .refusal_reasons
        .iter()
        .any(|reason| { reason.contains("receipt signer") || reason.contains("anchors") }));

    assert!(verify_portable_assurance_bytes(&bytes, &trusted).accepted);

    let mut different_configuration = trusted.clone();
    different_configuration.configuration_hash[0] ^= 1;
    different_configuration
        .required_guarantees
        .configuration_hash = Some(different_configuration.configuration_hash);
    let report = verify_portable_assurance_bytes(&bytes, &different_configuration);
    assert!(!report.accepted);
    assert!(report
        .refusal_reasons
        .iter()
        .any(|reason| reason.contains("network/configuration/epoch")));

    let mut unaffordable = trusted.clone();
    let collateral = receipt
        .claimed_achieved
        .slashable_collateral
        .as_ref()
        .expect("fixture has collateral");
    unaffordable
        .required_guarantees
        .minimum_slashable_collateral = Some(SlashableCollateralRequirementV1 {
        asset_id_hash: collateral.asset_id_hash,
        minimum_amount_base_units: (collateral.amount_base_units.parse::<u128>().unwrap() + 1)
            .to_string(),
    });
    let report = verify_portable_assurance_bytes(&bytes, &unaffordable);
    assert!(!report.accepted);
    assert!(report
        .refusal_reasons
        .iter()
        .any(|reason| reason.contains("relying-party policy")));
}
