use super::*;
use crate::config::AttestationSignaturePolicy;
use futures::stream;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::bls::BlsKeyPair;
use ioi_crypto::sign::guardian_committee::{
    decode_signers_bitfield, verify_quorum_certificate, verify_witness_certificate,
};
use ioi_ipc::control::guardian_control_server::{GuardianControl, GuardianControlServer};
use ioi_ipc::control::{
    LoadAssignedRecoveryShareRequest, LoadAssignedRecoveryShareResponse,
    ObserveAsymptoteRequest, ObserveAsymptoteResponse, ReportWitnessFaultRequest,
    ReportWitnessFaultResponse, SealConsensusRequest, SealConsensusResponse,
    SecureEgressRequest, SecureEgressResponse, SignCommitteeDecisionRequest,
    SignCommitteeDecisionResponse, SignConsensusRequest, SignConsensusResponse,
    SignWitnessStatementRequest, SignWitnessStatementResponse,
};
use ioi_types::app::{
    AssignedRecoveryShareEnvelopeV1, GuardianProductionMode, KeyAuthorityDescriptor,
    KeyAuthorityKind, RecoveryCodingDescriptor, RecoveryCodingFamily, RecoveryShareMaterial,
};
use ioi_types::config::{
    GuardianCommitteeConfig, GuardianCommitteeMemberConfig, GuardianTransparencyLogConfig,
    GuardianWitnessCommitteeConfig,
};
use rcgen::{BasicConstraints, IsCa};
use tempfile;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use tonic::{transport::Server, Request, Response, Status};

#[derive(Clone)]
struct MockRemoteCommitteeSigner {
    member_index: usize,
    signing_key: BlsPrivateKey,
}

#[tonic::async_trait]
impl GuardianControl for MockRemoteCommitteeSigner {
    async fn secure_egress(
        &self,
        _request: Request<SecureEgressRequest>,
    ) -> Result<Response<SecureEgressResponse>, Status> {
        Err(Status::unimplemented("unused in remote committee tests"))
    }

    async fn sign_consensus(
        &self,
        _request: Request<SignConsensusRequest>,
    ) -> Result<Response<SignConsensusResponse>, Status> {
        Err(Status::unimplemented("unused in remote committee tests"))
    }

    async fn seal_consensus(
        &self,
        _request: Request<SealConsensusRequest>,
    ) -> Result<Response<SealConsensusResponse>, Status> {
        Err(Status::unimplemented("unused in remote committee tests"))
    }

    async fn observe_asymptote(
        &self,
        _request: Request<ObserveAsymptoteRequest>,
    ) -> Result<Response<ObserveAsymptoteResponse>, Status> {
        Err(Status::unimplemented("unused in remote committee tests"))
    }

    async fn sign_committee_decision(
        &self,
        request: Request<SignCommitteeDecisionRequest>,
    ) -> Result<Response<SignCommitteeDecisionResponse>, Status> {
        let request = request.into_inner();
        let decision: GuardianDecision = codec::from_bytes_canonical(&request.decision)
            .map_err(|e| Status::invalid_argument(format!("invalid decision payload: {e}")))?;
        let decision_hash =
            canonical_decision_hash(&decision).map_err(|e| Status::internal(e.to_string()))?;
        let signature = self
            .signing_key
            .sign(&decision_hash)
            .map_err(|e| Status::internal(e.to_string()))?;
        let member_index = u32::try_from(self.member_index)
            .map_err(|_| Status::internal("member index overflow"))?;

        Ok(Response::new(SignCommitteeDecisionResponse {
            manifest_hash: request.manifest_hash,
            decision_hash: decision_hash.to_vec(),
            partial_signatures: vec![GuardianMemberSignature {
                member_index,
                signature: signature.to_bytes(),
            }],
        }))
    }

    async fn sign_witness_statement(
        &self,
        _request: Request<SignWitnessStatementRequest>,
    ) -> Result<Response<SignWitnessStatementResponse>, Status> {
        Err(Status::unimplemented("unused in remote committee tests"))
    }

    async fn load_assigned_recovery_share(
        &self,
        _request: Request<LoadAssignedRecoveryShareRequest>,
    ) -> Result<Response<LoadAssignedRecoveryShareResponse>, Status> {
        Err(Status::unimplemented("unused in remote committee tests"))
    }

    async fn report_witness_fault(
        &self,
        _request: Request<ReportWitnessFaultRequest>,
    ) -> Result<Response<ReportWitnessFaultResponse>, Status> {
        Err(Status::unimplemented("unused in remote committee tests"))
    }
}

async fn spawn_mock_remote_committee_server(
    service: MockRemoteCommitteeSigner,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = stream::unfold(listener, |listener| async move {
        match listener.accept().await {
            Ok((stream, _)) => Some((Ok::<_, std::io::Error>(stream), listener)),
            Err(error) => Some((Err(error), listener)),
        }
    });
    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(GuardianControlServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    sleep(Duration::from_millis(50)).await;
    (format!("http://{addr}"), handle)
}

async fn read_http_request<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut expected_total_len = None;

    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = header_end + 4;
            if expected_total_len.is_none() {
                let headers = String::from_utf8_lossy(&buffer[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                expected_total_len = Some(header_end + content_length);
            }
            if buffer.len() >= expected_total_len.unwrap_or(header_end) {
                return Ok(buffer);
            }
        }
    }

    Err(anyhow!("incomplete HTTP request"))
}

async fn spawn_tls_test_server(
    tempdir: &tempfile::TempDir,
) -> Result<(u16, String, [u8; 32], tokio::task::JoinHandle<()>)> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let mut ca_params = CertificateParams::new(vec!["IOI Test CA".to_string()])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_keypair = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_keypair)?;
    let ca_pem_path = tempdir.path().join("test-ca.pem");
    std::fs::write(&ca_pem_path, ca_cert.pem())?;

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()])?;
    server_params.subject_alt_names = vec![SanType::DnsName(
        Ia5String::try_from("localhost".to_string()).unwrap(),
    )];
    let server_keypair = KeyPair::generate()?;
    let server_cert = server_params.signed_by(&server_keypair, &ca_cert, &ca_keypair)?;
    let leaf_hash =
        digest_to_array(Sha256::digest(server_cert.der().as_ref()).map_err(|e| anyhow!(e))?)?;
    let cert_chain = vec![server_cert.der().clone()];
    let private_key = PrivatePkcs8KeyDer::from(server_keypair.serialize_der());
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key.into())?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();
        let _request = read_http_request(&mut tls_stream).await.unwrap();
        tls_stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .unwrap();
        let _ = tls_stream.shutdown().await;
    });

    Ok((port, ca_pem_path.display().to_string(), leaf_hash, handle))
}

#[test]
fn test_no_plaintext_at_rest() {
    let seed = [0xAAu8; 32]; // Distinct pattern to search for
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guardian.key");

    // Mock the environment variable for passphrase
    unsafe { std::env::set_var("IOI_GUARDIAN_KEY_PASS", "test_pass") };

    // Write key using the new atomic save_encrypted_file
    GuardianContainer::save_encrypted_file(&path, &seed).expect("Save failed");

    // Verify file exists
    assert!(path.exists());

    // Read raw file content
    let content = std::fs::read(&path).expect("Read failed");

    // 1. Verify Magic Header
    assert_eq!(&content[0..8], b"IOI-GKEY", "Header mismatch");

    // 2. Scan entire file to ensure the raw seed pattern does not appear
    assert!(
        content.windows(32).all(|window| window != seed),
        "Plaintext seed found on disk! Encryption failed."
    );

    // 3. Verify we can decrypt it back
    let loaded = GuardianContainer::load_encrypted_file(&path).expect("Load failed");
    assert_eq!(loaded, seed.to_vec(), "Roundtrip mismatch");
}

#[tokio::test]
async fn guardian_slot_lock_rejects_conflicting_payloads_for_same_slot() {
    let dir = tempfile::tempdir().unwrap();
    let mut members = Vec::new();
    for index in 0..3 {
        let keypair = BlsKeyPair::generate().unwrap();
        let private_key_path = dir.path().join(format!("member-{index}.bls"));
        std::fs::write(
            &private_key_path,
            hex::encode(keypair.private_key().to_bytes()),
        )
        .unwrap();
        members.push(GuardianCommitteeMemberConfig {
            member_id: format!("member-{index}"),
            endpoint: None,
            public_key: keypair.public_key().to_bytes(),
            private_key_path: Some(private_key_path.display().to_string()),
            provider: Some(format!("provider-{index}")),
            region: Some(format!("region-{}", index % 2)),
            host_class: Some(format!("host-{index}")),
            key_authority_kind: Some(KeyAuthorityKind::CloudKms),
        });
    }

    let config = GuardianConfig {
        signature_policy: AttestationSignaturePolicy::Fixed,
        production_mode: GuardianProductionMode::Development,
        key_authority: Some(KeyAuthorityDescriptor {
            kind: KeyAuthorityKind::DevMemory,
            ..Default::default()
        }),
        committee: GuardianCommitteeConfig {
            threshold: 2,
            members,
            transparency_log_id: "guardian-test".into(),
        },
        experimental_witness_committees: Vec::new(),
        hardening: Default::default(),
        transparency_log: GuardianTransparencyLogConfig {
            log_id: "guardian-test".into(),
            endpoint: None,
            signing_key_path: None,
            required: false,
        },
        verifier_policy: Default::default(),
        enforce_binary_integrity: false,
        approved_orchestrator_hash: None,
        approved_workload_hash: None,
        binary_dir_override: None,
    };
    let validator_account_id = AccountId([9u8; 32]);
    let container =
        GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap();
    let signer = libp2p::identity::Keypair::generate_ed25519();

    let first_bundle = container
        .sign_consensus_with_guardian(
            &signer,
            [1u8; 32],
            42,
            7,
            validator_account_id.0.to_vec(),
            0,
            [0u8; 32],
            None,
            None,
            None,
            None,
            0,
            None,
        )
        .await
        .unwrap();
    assert!(first_bundle.guardian_certificate.is_some());

    let err = container
        .sign_consensus_with_guardian(
            &signer,
            [2u8; 32],
            42,
            7,
            validator_account_id.0.to_vec(),
            first_bundle.counter,
            first_bundle.trace_hash,
            None,
            None,
            None,
            None,
            0,
            None,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("slot already certified"));
}

fn build_test_guardian_container(
    dir: &tempfile::TempDir,
    validator_account_id: AccountId,
    epoch: u64,
) -> GuardianContainer {
    let mut members = Vec::new();
    for index in 0..3 {
        let keypair = BlsKeyPair::generate().unwrap();
        let private_key_path = dir.path().join(format!("member-{index}.bls"));
        std::fs::write(
            &private_key_path,
            hex::encode(keypair.private_key().to_bytes()),
        )
        .unwrap();
        members.push(GuardianCommitteeMemberConfig {
            member_id: format!("member-{index}"),
            endpoint: None,
            public_key: keypair.public_key().to_bytes(),
            private_key_path: Some(private_key_path.display().to_string()),
            provider: Some(format!("provider-{index}")),
            region: Some(format!("region-{index}")),
            host_class: Some(format!("host-{index}")),
            key_authority_kind: Some(KeyAuthorityKind::CloudKms),
        });
    }

    let config = GuardianConfig {
        signature_policy: AttestationSignaturePolicy::Fixed,
        production_mode: GuardianProductionMode::Development,
        key_authority: Some(KeyAuthorityDescriptor {
            kind: KeyAuthorityKind::DevMemory,
            ..Default::default()
        }),
        committee: GuardianCommitteeConfig {
            threshold: 2,
            members,
            transparency_log_id: "guardian-test".into(),
        },
        experimental_witness_committees: Vec::new(),
        hardening: Default::default(),
        transparency_log: GuardianTransparencyLogConfig {
            log_id: "guardian-test".into(),
            endpoint: None,
            signing_key_path: None,
            required: false,
        },
        verifier_policy: Default::default(),
        enforce_binary_integrity: false,
        approved_orchestrator_hash: None,
        approved_workload_hash: None,
        binary_dir_override: None,
    };
    let container =
        GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap();
    assert_eq!(
        container
            .committee_client
            .as_ref()
            .expect("guardian committee should be configured")
            .manifest
            .epoch,
        epoch
    );
    container
}

fn build_test_guardian_container_with_witness_committee(
    dir: &tempfile::TempDir,
    validator_account_id: AccountId,
    witness_epoch: u64,
) -> (GuardianContainer, [u8; 32]) {
    let mut guardian_members = Vec::new();
    for index in 0..3 {
        let keypair = BlsKeyPair::generate().unwrap();
        let private_key_path = dir.path().join(format!("guardian-member-{index}.bls"));
        std::fs::write(
            &private_key_path,
            hex::encode(keypair.private_key().to_bytes()),
        )
        .unwrap();
        guardian_members.push(GuardianCommitteeMemberConfig {
            member_id: format!("guardian-{index}"),
            endpoint: None,
            public_key: keypair.public_key().to_bytes(),
            private_key_path: Some(private_key_path.display().to_string()),
            provider: Some(format!("provider-{index}")),
            region: Some(format!("region-{index}")),
            host_class: Some(format!("host-{index}")),
            key_authority_kind: Some(KeyAuthorityKind::CloudKms),
        });
    }

    let mut witness_members = Vec::new();
    for index in 0..3 {
        let keypair = BlsKeyPair::generate().unwrap();
        let private_key_path = dir.path().join(format!("witness-member-{index}.bls"));
        std::fs::write(
            &private_key_path,
            hex::encode(keypair.private_key().to_bytes()),
        )
        .unwrap();
        witness_members.push(GuardianCommitteeMemberConfig {
            member_id: format!("witness-{index}"),
            endpoint: None,
            public_key: keypair.public_key().to_bytes(),
            private_key_path: Some(private_key_path.display().to_string()),
            provider: Some(format!("witness-provider-{index}")),
            region: Some(format!("witness-region-{index}")),
            host_class: Some(format!("witness-host-{index}")),
            key_authority_kind: Some(KeyAuthorityKind::Tpm2),
        });
    }

    let config = GuardianConfig {
        signature_policy: AttestationSignaturePolicy::Fixed,
        production_mode: GuardianProductionMode::Development,
        key_authority: Some(KeyAuthorityDescriptor {
            kind: KeyAuthorityKind::DevMemory,
            ..Default::default()
        }),
        committee: GuardianCommitteeConfig {
            threshold: 2,
            members: guardian_members,
            transparency_log_id: "guardian-test".into(),
        },
        experimental_witness_committees: vec![GuardianWitnessCommitteeConfig {
            committee_id: "witness-a".into(),
            stratum_id: "stratum-a".into(),
            epoch: witness_epoch,
            threshold: 2,
            members: witness_members,
            transparency_log_id: "witness-test".into(),
            policy_hash: Some([0x88u8; 32]),
        }],
        hardening: Default::default(),
        transparency_log: GuardianTransparencyLogConfig {
            log_id: "guardian-test".into(),
            endpoint: None,
            signing_key_path: None,
            required: false,
        },
        verifier_policy: Default::default(),
        enforce_binary_integrity: false,
        approved_orchestrator_hash: None,
        approved_workload_hash: None,
        binary_dir_override: None,
    };

    let witness_manifest_hash = GuardianWitnessCommitteeClient::from_configs(&config)
        .unwrap()
        .into_keys()
        .next()
        .expect("expected one witness manifest");
    (
        GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap(),
        witness_manifest_hash,
    )
}

fn sample_assigned_recovery_share_envelope(
    witness_manifest_hash: [u8; 32],
    height: u64,
    recovery_binding: GuardianWitnessRecoveryBinding,
) -> AssignedRecoveryShareEnvelopeV1 {
    AssignedRecoveryShareEnvelopeV1 {
        recovery_capsule_hash: recovery_binding.recovery_capsule_hash,
        expected_share_commitment_hash: recovery_binding.share_commitment_hash,
        share_material: RecoveryShareMaterial {
            height,
            witness_manifest_hash,
            block_commitment_hash: [0xa4u8; 32],
            coding: RecoveryCodingDescriptor {
                family: RecoveryCodingFamily::SystematicXorKOfKPlus1V1,
                share_count: 3,
                recovery_threshold: 2,
            },
            share_index: 1,
            share_commitment_hash: recovery_binding.share_commitment_hash,
            material_bytes: vec![0x10, 0x20, 0x30, 0x40],
        },
    }
}

#[tokio::test]
async fn observe_asymptote_request_returns_transcript_for_valid_request() {
    let dir = tempfile::tempdir().unwrap();
    let validator_account_id = AccountId([0x31u8; 32]);
    let epoch = 1;
    let container = build_test_guardian_container(&dir, validator_account_id, epoch);
    let manifest_hash = container.committee_client.as_ref().unwrap().manifest_hash();
    let request = AsymptoteObserverObservationRequest {
        epoch,
        assignment: ioi_types::app::AsymptoteObserverAssignment {
            epoch,
            producer_account_id: AccountId([0x21u8; 32]),
            height: 17,
            view: 3,
            round: 1,
            observer_account_id: validator_account_id,
        },
        block_hash: [0x11u8; 32],
        guardian_manifest_hash: [0x22u8; 32],
        guardian_decision_hash: [0x33u8; 32],
        guardian_counter: 9,
        guardian_trace_hash: [0x44u8; 32],
        guardian_measurement_root: [0x55u8; 32],
        guardian_checkpoint_root: [0x66u8; 32],
    };

    let observation = container
        .observe_asymptote_request(&request, Some(manifest_hash))
        .await
        .unwrap();
    assert!(observation.challenge.is_none());
    let transcript = observation
        .transcript
        .expect("valid request should produce a transcript");
    assert_eq!(
        transcript.statement,
        GuardianContainer::observation_request_statement(&request)
    );
    assert_eq!(transcript.statement.assignment, request.assignment);
    assert!(transcript.guardian_certificate.log_checkpoint.is_some());
}

#[tokio::test]
async fn observe_asymptote_request_returns_transcript_mismatch_challenge_for_malformed_request()
{
    let dir = tempfile::tempdir().unwrap();
    let validator_account_id = AccountId([0x41u8; 32]);
    let epoch = 1;
    let container = build_test_guardian_container(&dir, validator_account_id, epoch);
    let manifest_hash = container.committee_client.as_ref().unwrap().manifest_hash();
    let request = AsymptoteObserverObservationRequest {
        epoch,
        assignment: ioi_types::app::AsymptoteObserverAssignment {
            epoch,
            producer_account_id: AccountId([0x22u8; 32]),
            height: 19,
            view: 5,
            round: 0,
            observer_account_id: validator_account_id,
        },
        block_hash: [0u8; 32],
        guardian_manifest_hash: [0x52u8; 32],
        guardian_decision_hash: [0x53u8; 32],
        guardian_counter: 12,
        guardian_trace_hash: [0x54u8; 32],
        guardian_measurement_root: [0x55u8; 32],
        guardian_checkpoint_root: [0x56u8; 32],
    };

    let observation = container
        .observe_asymptote_request(&request, Some(manifest_hash))
        .await
        .unwrap();
    assert!(observation.transcript.is_none());
    let challenge = observation
        .challenge
        .expect("malformed request should produce a transcript-mismatch challenge");
    assert_eq!(
        challenge.kind,
        AsymptoteObserverChallengeKind::TranscriptMismatch
    );
    assert_eq!(challenge.assignment, Some(request.assignment.clone()));
    assert_eq!(challenge.observation_request, Some(request.clone()));
    assert!(challenge.transcript.is_none());
    assert_eq!(
        challenge.evidence_hash,
        canonical_asymptote_observer_observation_request_hash(&request).unwrap()
    );
}

#[tokio::test]
async fn guardian_committee_collects_remote_partial_signatures() {
    let remote_key = BlsKeyPair::generate().unwrap();
    let (remote_endpoint, server_handle) =
        spawn_mock_remote_committee_server(MockRemoteCommitteeSigner {
            member_index: 1,
            signing_key: remote_key.private_key(),
        })
        .await;

    let dir = tempfile::tempdir().unwrap();
    let local_key = BlsKeyPair::generate().unwrap();
    let local_private_key_path = dir.path().join("member-0.bls");
    std::fs::write(
        &local_private_key_path,
        hex::encode(local_key.private_key().to_bytes()),
    )
    .unwrap();

    let members = vec![
        GuardianCommitteeMemberConfig {
            member_id: "member-0".into(),
            endpoint: None,
            public_key: local_key.public_key().to_bytes(),
            private_key_path: Some(local_private_key_path.display().to_string()),
            provider: Some("provider-a".into()),
            region: Some("us-east-1".into()),
            host_class: Some("host-a".into()),
            key_authority_kind: Some(KeyAuthorityKind::CloudKms),
        },
        GuardianCommitteeMemberConfig {
            member_id: "member-1".into(),
            endpoint: Some(remote_endpoint.clone()),
            public_key: remote_key.public_key().to_bytes(),
            private_key_path: None,
            provider: Some("provider-b".into()),
            region: Some("us-west-2".into()),
            host_class: Some("host-b".into()),
            key_authority_kind: Some(KeyAuthorityKind::Tpm2),
        },
    ];
    let config = GuardianConfig {
        signature_policy: AttestationSignaturePolicy::Fixed,
        production_mode: GuardianProductionMode::Development,
        key_authority: Some(KeyAuthorityDescriptor {
            kind: KeyAuthorityKind::DevMemory,
            ..Default::default()
        }),
        committee: GuardianCommitteeConfig {
            threshold: 2,
            members,
            transparency_log_id: "guardian-test".into(),
        },
        experimental_witness_committees: Vec::new(),
        hardening: Default::default(),
        transparency_log: GuardianTransparencyLogConfig {
            log_id: "guardian-test".into(),
            endpoint: None,
            signing_key_path: None,
            required: false,
        },
        verifier_policy: Default::default(),
        enforce_binary_integrity: false,
        approved_orchestrator_hash: None,
        approved_workload_hash: None,
        binary_dir_override: None,
    };
    let validator_account_id = AccountId([5u8; 32]);
    let committee_client = GuardianCommitteeClient::from_config(&config, validator_account_id)
        .unwrap()
        .unwrap();
    let container =
        GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let payload_hash = [9u8; 32];

    let bundle = container
        .sign_consensus_with_guardian(
            &signer,
            payload_hash,
            17,
            3,
            validator_account_id.0.to_vec(),
            0,
            [0u8; 32],
            None,
            None,
            None,
            None,
            0,
            None,
        )
        .await
        .unwrap();
    let certificate = bundle.guardian_certificate.clone().unwrap();
    let signer_indexes = decode_signers_bitfield(
        committee_client.manifest.members.len(),
        &certificate.signers_bitfield,
    )
    .unwrap();
    assert_eq!(signer_indexes, vec![0, 1]);

    let decision = GuardianDecision {
        domain: GuardianDecisionDomain::ConsensusSlot as u8,
        subject: validator_account_id.0.to_vec(),
        payload_hash,
        counter: certificate.counter,
        trace_hash: certificate.trace_hash,
        measurement_root: certificate.measurement_root,
        policy_hash: committee_client.default_policy_hash(),
    };
    verify_quorum_certificate(&committee_client.manifest, &decision, &certificate).unwrap();

    server_handle.abort();
}

#[tokio::test]
async fn guardian_sign_consensus_issues_experimental_witness_certificate() {
    let dir = tempfile::tempdir().unwrap();

    let mut guardian_members = Vec::new();
    for index in 0..3 {
        let keypair = BlsKeyPair::generate().unwrap();
        let private_key_path = dir.path().join(format!("guardian-member-{index}.bls"));
        std::fs::write(
            &private_key_path,
            hex::encode(keypair.private_key().to_bytes()),
        )
        .unwrap();
        guardian_members.push(GuardianCommitteeMemberConfig {
            member_id: format!("guardian-{index}"),
            endpoint: None,
            public_key: keypair.public_key().to_bytes(),
            private_key_path: Some(private_key_path.display().to_string()),
            provider: Some(format!("provider-{index}")),
            region: Some(format!("region-{index}")),
            host_class: Some(format!("host-{index}")),
            key_authority_kind: Some(KeyAuthorityKind::CloudKms),
        });
    }

    let mut witness_members = Vec::new();
    for index in 0..3 {
        let keypair = BlsKeyPair::generate().unwrap();
        let private_key_path = dir.path().join(format!("witness-member-{index}.bls"));
        std::fs::write(
            &private_key_path,
            hex::encode(keypair.private_key().to_bytes()),
        )
        .unwrap();
        witness_members.push(GuardianCommitteeMemberConfig {
            member_id: format!("witness-{index}"),
            endpoint: None,
            public_key: keypair.public_key().to_bytes(),
            private_key_path: Some(private_key_path.display().to_string()),
            provider: Some(format!("witness-provider-{index}")),
            region: Some(format!("witness-region-{index}")),
            host_class: Some(format!("witness-host-{index}")),
            key_authority_kind: Some(KeyAuthorityKind::Tpm2),
        });
    }

    let config = GuardianConfig {
        signature_policy: AttestationSignaturePolicy::Fixed,
        production_mode: GuardianProductionMode::Development,
        key_authority: Some(KeyAuthorityDescriptor {
            kind: KeyAuthorityKind::DevMemory,
            ..Default::default()
        }),
        committee: GuardianCommitteeConfig {
            threshold: 2,
            members: guardian_members,
            transparency_log_id: "guardian-test".into(),
        },
        experimental_witness_committees: vec![GuardianWitnessCommitteeConfig {
            committee_id: "witness-a".into(),
            stratum_id: "stratum-a".into(),
            epoch: 7,
            threshold: 2,
            members: witness_members,
            transparency_log_id: "witness-test".into(),
            policy_hash: Some([0x77u8; 32]),
        }],
        hardening: Default::default(),
        transparency_log: GuardianTransparencyLogConfig {
            log_id: "guardian-test".into(),
            endpoint: None,
            signing_key_path: None,
            required: false,
        },
        verifier_policy: Default::default(),
        enforce_binary_integrity: false,
        approved_orchestrator_hash: None,
        approved_workload_hash: None,
        binary_dir_override: None,
    };

    let validator_account_id = AccountId([7u8; 32]);
    let witness_clients = GuardianWitnessCommitteeClient::from_configs(&config).unwrap();
    let (&witness_manifest_hash, witness_client) = witness_clients.iter().next().unwrap();
    let container =
        GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let payload_hash = [0x42u8; 32];

    let bundle = container
        .sign_consensus_with_guardian(
            &signer,
            payload_hash,
            21,
            4,
            validator_account_id.0.to_vec(),
            0,
            [0u8; 32],
            None,
            None,
            None,
            Some(witness_manifest_hash),
            0,
            None,
        )
        .await
        .unwrap();

    let guardian_certificate = bundle.guardian_certificate.unwrap();
    let witness_certificate = guardian_certificate
        .experimental_witness_certificate
        .clone()
        .expect("expected experimental witness certificate");
    assert_eq!(witness_certificate.manifest_hash, witness_manifest_hash);
    assert_eq!(witness_certificate.reassignment_depth, 0);
    assert!(witness_certificate.recovery_binding.is_none());
    assert!(witness_certificate.log_checkpoint.is_some());

    let statement = GuardianWitnessStatement {
        producer_account_id: validator_account_id,
        height: 21,
        view: 4,
        guardian_manifest_hash: guardian_certificate.manifest_hash,
        guardian_decision_hash: guardian_certificate.decision_hash,
        guardian_counter: guardian_certificate.counter,
        guardian_trace_hash: guardian_certificate.trace_hash,
        guardian_measurement_root: guardian_certificate.measurement_root,
        guardian_checkpoint_root: guardian_certificate
            .log_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.root_hash)
            .unwrap_or([0u8; 32]),
        recovery_binding: witness_certificate.recovery_binding.clone(),
    };
    verify_witness_certificate(&witness_client.manifest, &statement, &witness_certificate)
        .unwrap();
}

#[tokio::test]
async fn guardian_sign_consensus_issues_experimental_witness_certificate_with_recovery_binding()
{
    let dir = tempfile::tempdir().unwrap();

    let mut guardian_members = Vec::new();
    for index in 0..3 {
        let keypair = BlsKeyPair::generate().unwrap();
        let private_key_path = dir.path().join(format!("guardian-member-{index}.bls"));
        std::fs::write(
            &private_key_path,
            hex::encode(keypair.private_key().to_bytes()),
        )
        .unwrap();
        guardian_members.push(GuardianCommitteeMemberConfig {
            member_id: format!("guardian-{index}"),
            endpoint: None,
            public_key: keypair.public_key().to_bytes(),
            private_key_path: Some(private_key_path.display().to_string()),
            provider: Some(format!("provider-{index}")),
            region: Some(format!("region-{index}")),
            host_class: Some(format!("host-{index}")),
            key_authority_kind: Some(KeyAuthorityKind::CloudKms),
        });
    }

    let mut witness_members = Vec::new();
    for index in 0..3 {
        let keypair = BlsKeyPair::generate().unwrap();
        let private_key_path = dir.path().join(format!("witness-member-{index}.bls"));
        std::fs::write(
            &private_key_path,
            hex::encode(keypair.private_key().to_bytes()),
        )
        .unwrap();
        witness_members.push(GuardianCommitteeMemberConfig {
            member_id: format!("witness-{index}"),
            endpoint: None,
            public_key: keypair.public_key().to_bytes(),
            private_key_path: Some(private_key_path.display().to_string()),
            provider: Some(format!("witness-provider-{index}")),
            region: Some(format!("witness-region-{index}")),
            host_class: Some(format!("witness-host-{index}")),
            key_authority_kind: Some(KeyAuthorityKind::Tpm2),
        });
    }

    let config = GuardianConfig {
        signature_policy: AttestationSignaturePolicy::Fixed,
        production_mode: GuardianProductionMode::Development,
        key_authority: Some(KeyAuthorityDescriptor {
            kind: KeyAuthorityKind::DevMemory,
            ..Default::default()
        }),
        committee: GuardianCommitteeConfig {
            threshold: 2,
            members: guardian_members,
            transparency_log_id: "guardian-test".into(),
        },
        experimental_witness_committees: vec![GuardianWitnessCommitteeConfig {
            committee_id: "witness-a".into(),
            stratum_id: "stratum-a".into(),
            epoch: 7,
            threshold: 2,
            members: witness_members,
            transparency_log_id: "witness-test".into(),
            policy_hash: Some([0x88u8; 32]),
        }],
        hardening: Default::default(),
        transparency_log: GuardianTransparencyLogConfig {
            log_id: "guardian-test".into(),
            endpoint: None,
            signing_key_path: None,
            required: false,
        },
        verifier_policy: Default::default(),
        enforce_binary_integrity: false,
        approved_orchestrator_hash: None,
        approved_workload_hash: None,
        binary_dir_override: None,
    };

    let validator_account_id = AccountId([8u8; 32]);
    let witness_clients = GuardianWitnessCommitteeClient::from_configs(&config).unwrap();
    let (&witness_manifest_hash, witness_client) = witness_clients.iter().next().unwrap();
    let container =
        GuardianContainer::new(dir.path().to_path_buf(), config, validator_account_id).unwrap();
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let payload_hash = [0x43u8; 32];
    let recovery_binding = GuardianWitnessRecoveryBinding {
        recovery_capsule_hash: [0x51u8; 32],
        share_commitment_hash: [0x52u8; 32],
    };

    let bundle = container
        .sign_consensus_with_guardian(
            &signer,
            payload_hash,
            22,
            5,
            validator_account_id.0.to_vec(),
            0,
            [0u8; 32],
            None,
            None,
            None,
            Some(witness_manifest_hash),
            0,
            Some(recovery_binding.clone()),
        )
        .await
        .unwrap();

    let guardian_certificate = bundle.guardian_certificate.unwrap();
    let witness_certificate = guardian_certificate
        .experimental_witness_certificate
        .clone()
        .expect("expected experimental witness certificate");
    assert_eq!(witness_certificate.manifest_hash, witness_manifest_hash);
    assert_eq!(
        witness_certificate.recovery_binding,
        Some(recovery_binding.clone())
    );

    let statement = GuardianWitnessStatement {
        producer_account_id: validator_account_id,
        height: 22,
        view: 5,
        guardian_manifest_hash: guardian_certificate.manifest_hash,
        guardian_decision_hash: guardian_certificate.decision_hash,
        guardian_counter: guardian_certificate.counter,
        guardian_trace_hash: guardian_certificate.trace_hash,
        guardian_measurement_root: guardian_certificate.measurement_root,
        guardian_checkpoint_root: guardian_certificate
            .log_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.root_hash)
            .unwrap_or([0u8; 32]),
        recovery_binding: Some(recovery_binding),
    };
    verify_witness_certificate(&witness_client.manifest, &statement, &witness_certificate)
        .unwrap();
}

#[tokio::test]
async fn guardian_issue_experimental_witness_certificate_persists_assigned_recovery_share() {
    let dir = tempfile::tempdir().unwrap();
    let validator_account_id = AccountId([0x91u8; 32]);
    let (container, witness_manifest_hash) =
        build_test_guardian_container_with_witness_committee(&dir, validator_account_id, 11);
    let signer = libp2p::identity::Keypair::generate_ed25519();
    let guardian_certificate = container
        .sign_consensus_with_guardian(
            &signer,
            [0x61u8; 32],
            33,
            6,
            validator_account_id.0.to_vec(),
            0,
            [0u8; 32],
            None,
            None,
            None,
            None,
            0,
            None,
        )
        .await
        .unwrap()
        .guardian_certificate
        .expect("guardian certificate");
    let recovery_binding = GuardianWitnessRecoveryBinding {
        recovery_capsule_hash: [0x71u8; 32],
        share_commitment_hash: [0x72u8; 32],
    };
    let recovery_share_envelope = sample_assigned_recovery_share_envelope(
        witness_manifest_hash,
        33,
        recovery_binding.clone(),
    );

    let witness_certificate = container
        .issue_experimental_witness_certificate(
            &guardian_certificate,
            witness_manifest_hash,
            0,
            validator_account_id,
            33,
            6,
            Some(recovery_binding.clone()),
            Some(&recovery_share_envelope),
        )
        .await
        .unwrap();

    assert_eq!(witness_certificate.manifest_hash, witness_manifest_hash);
    assert_eq!(
        witness_certificate.recovery_binding,
        Some(recovery_binding.clone())
    );
    let stored = container
        .load_assigned_recovery_share_envelope(witness_manifest_hash, 33, &recovery_binding)
        .unwrap()
        .expect("stored assigned recovery share envelope");
    assert_eq!(stored, recovery_share_envelope);
    let stored_material = container
        .load_assigned_recovery_share_material(witness_manifest_hash, 33, &recovery_binding)
        .unwrap()
        .expect("stored assigned recovery share material");
    assert_eq!(stored_material, recovery_share_envelope.share_material);
    assert_eq!(
        stored.share_material.to_recovery_share_receipt(),
        ioi_types::app::RecoveryShareReceipt {
            height: 33,
            witness_manifest_hash,
            block_commitment_hash: [0xa4u8; 32],
            share_commitment_hash: [0x72u8; 32],
        }
    );
}

#[tokio::test]
async fn guardian_sign_witness_statement_members_rejects_malformed_recovery_share_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let validator_account_id = AccountId([0x92u8; 32]);
    let (container, witness_manifest_hash) =
        build_test_guardian_container_with_witness_committee(&dir, validator_account_id, 12);
    let recovery_binding = GuardianWitnessRecoveryBinding {
        recovery_capsule_hash: [0x81u8; 32],
        share_commitment_hash: [0x82u8; 32],
    };
    let statement = GuardianWitnessStatement {
        producer_account_id: validator_account_id,
        height: 34,
        view: 7,
        guardian_manifest_hash: [0x83u8; 32],
        guardian_decision_hash: [0x84u8; 32],
        guardian_counter: 9,
        guardian_trace_hash: [0x85u8; 32],
        guardian_measurement_root: [0x86u8; 32],
        guardian_checkpoint_root: [0x87u8; 32],
        recovery_binding: Some(recovery_binding.clone()),
    };
    let mut malformed =
        sample_assigned_recovery_share_envelope(witness_manifest_hash, 34, recovery_binding);
    malformed.share_material.witness_manifest_hash = [0xffu8; 32];

    let error = container
        .sign_witness_statement_members(
            &statement,
            Some(witness_manifest_hash),
            Some(&malformed),
        )
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("assigned recovery share envelope witness manifest does not match"));
}

#[tokio::test]
async fn notarized_https_request_enforces_tls_policy_and_hashes_peer_chain() {
    let tempdir = tempfile::tempdir().unwrap();
    let (port, ca_pem_path, leaf_hash, server_handle) =
        spawn_tls_test_server(&tempdir).await.unwrap();
    let policy = GuardianVerifierPolicyConfig {
        tls_allowed_server_names: vec!["localhost".into()],
        tls_allowed_root_pem_paths: vec![ca_pem_path],
        tls_pinned_leaf_certificate_sha256: vec![hex::encode(leaf_hash)],
        tls_transcript_version: 1,
        ..Default::default()
    };

    let (
        response_bytes,
        server_name,
        chain_hash,
        returned_leaf_hash,
        handshake_hash,
        request_hash,
        response_hash,
    ) = notarized_https_request(
        &format!("localhost:{port}"),
        "/v1/test",
        "POST",
        br#"{"ping":"pong"}"#.to_vec(),
        Vec::new(),
        &policy,
    )
    .await
    .unwrap();

    assert_eq!(response_bytes, b"ok");
    assert_eq!(server_name, "localhost");
    assert_ne!(chain_hash, [0u8; 32]);
    assert_eq!(returned_leaf_hash, leaf_hash);
    assert_ne!(handshake_hash, [0u8; 32]);
    assert_ne!(request_hash, [0u8; 32]);
    assert_ne!(response_hash, [0u8; 32]);

    server_handle.abort();
}

#[tokio::test]
async fn notarized_https_request_rejects_server_name_policy_mismatch() {
    let tempdir = tempfile::tempdir().unwrap();
    let (port, ca_pem_path, _, server_handle) = spawn_tls_test_server(&tempdir).await.unwrap();
    let policy = GuardianVerifierPolicyConfig {
        tls_allowed_server_names: vec!["example.com".into()],
        tls_allowed_root_pem_paths: vec![ca_pem_path],
        tls_pinned_leaf_certificate_sha256: Vec::new(),
        tls_transcript_version: 1,
        ..Default::default()
    };

    let err = notarized_https_request(
        &format!("localhost:{port}"),
        "/v1/test",
        "POST",
        br#"{}"#.to_vec(),
        Vec::new(),
        &policy,
    )
    .await
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("is not allowed by verifier policy"));

    server_handle.abort();
}

#[tokio::test]
async fn notarized_https_request_rejects_leaf_pin_mismatch() {
    let tempdir = tempfile::tempdir().unwrap();
    let (port, ca_pem_path, _, server_handle) = spawn_tls_test_server(&tempdir).await.unwrap();
    let policy = GuardianVerifierPolicyConfig {
        tls_allowed_server_names: vec!["localhost".into()],
        tls_allowed_root_pem_paths: vec![ca_pem_path],
        tls_pinned_leaf_certificate_sha256: vec![hex::encode([0xAAu8; 32])],
        tls_transcript_version: 1,
        ..Default::default()
    };

    let err = notarized_https_request(
        &format!("localhost:{port}"),
        "/v1/test",
        "POST",
        br#"{}"#.to_vec(),
        Vec::new(),
        &policy,
    )
    .await
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("does not match any configured TLS pin"));

    server_handle.abort();
}

#[tokio::test]
async fn notarized_https_request_rejects_hostname_mismatch() {
    let tempdir = tempfile::tempdir().unwrap();
    let (port, ca_pem_path, leaf_hash, server_handle) =
        spawn_tls_test_server(&tempdir).await.unwrap();
    let policy = GuardianVerifierPolicyConfig {
        tls_allowed_server_names: vec!["127.0.0.1".into()],
        tls_allowed_root_pem_paths: vec![ca_pem_path],
        tls_pinned_leaf_certificate_sha256: vec![hex::encode(leaf_hash)],
        tls_transcript_version: 1,
        ..Default::default()
    };

    let err = notarized_https_request(
        &format!("127.0.0.1:{port}"),
        "/v1/test",
        "POST",
        br#"{}"#.to_vec(),
        Vec::new(),
        &policy,
    )
    .await
    .unwrap_err();
    assert!(!err.to_string().is_empty());

    server_handle.abort();
}
