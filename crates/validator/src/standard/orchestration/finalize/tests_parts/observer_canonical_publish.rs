#[test]
fn canonicalize_observer_sealed_finality_proof_rewrites_invalid_close_into_abort() {
    let header = sample_block_header();
    let policy = AsymptotePolicy {
        epoch: 9,
        observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
        observer_challenge_window_ms: 500,
        ..Default::default()
    };
    let assignment = ioi_types::app::AsymptoteObserverAssignment {
        epoch: 9,
        producer_account_id: header.producer_account_id,
        height: header.height,
        view: header.view,
        round: 0,
        observer_account_id: AccountId([42u8; 32]),
    };
    let transcripts = vec![AsymptoteObserverTranscript {
        statement: AsymptoteObserverStatement {
            epoch: 9,
            assignment: assignment.clone(),
            block_hash: [50u8; 32],
            guardian_manifest_hash: [51u8; 32],
            guardian_decision_hash: [52u8; 32],
            guardian_counter: 53,
            guardian_trace_hash: [54u8; 32],
            guardian_measurement_root: [55u8; 32],
            guardian_checkpoint_root: [56u8; 32],
            verdict: ioi_types::app::AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [57u8; 32],
        },
        guardian_certificate: header
            .guardian_certificate
            .clone()
            .expect("sample header must carry guardian certificate"),
    }];
    let assignments_hash =
        canonical_asymptote_observer_assignments_hash(&[assignment]).expect("assignment hash");
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&transcripts).expect("transcript root");
    let empty_challenges: Vec<AsymptoteObserverChallenge> = Vec::new();
    let empty_challenges_root = canonical_asymptote_observer_challenges_hash(&empty_challenges)
        .expect("empty challenge root");
    let invalid_close = AsymptoteObserverCanonicalClose {
        epoch: 9,
        height: header.height,
        view: header.view,
        assignments_hash,
        transcripts_root,
        challenges_root: empty_challenges_root,
        transcript_count: 1,
        challenge_count: 1,
        challenge_cutoff_timestamp_ms: header.timestamp_ms_or_legacy().saturating_add(500),
    };
    let mut proof = SealedFinalityProof {
        epoch: 9,
        finality_tier: ioi_types::app::FinalityTier::SealedFinal,
        collapse_state: ioi_types::app::CollapseState::SealedFinal,
        guardian_manifest_hash: [58u8; 32],
        guardian_decision_hash: [59u8; 32],
        guardian_counter: 60,
        guardian_trace_hash: [61u8; 32],
        guardian_measurement_root: [62u8; 32],
        policy_hash: [63u8; 32],
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: transcripts.clone(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: Some(AsymptoteObserverTranscriptCommitment {
            epoch: 9,
            height: header.height,
            view: header.view,
            assignments_hash,
            transcripts_root,
            transcript_count: 1,
        }),
        observer_challenge_commitment: Some(AsymptoteObserverChallengeCommitment {
            epoch: 9,
            height: header.height,
            view: header.view,
            challenges_root: empty_challenges_root,
            challenge_count: 0,
        }),
        observer_canonical_close: Some(invalid_close.clone()),
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    };

    let artifacts =
        canonicalize_observer_sealed_finality_proof(&header, &policy, [64u8; 32], &mut proof)
            .expect("canonicalization should succeed")
            .expect("invalid close should still yield canonical artifacts");

    assert_eq!(proof.finality_tier, ioi_types::app::FinalityTier::BaseFinal);
    assert_eq!(proof.collapse_state, ioi_types::app::CollapseState::Abort);
    assert!(proof.observer_canonical_close.is_none());
    assert!(proof.observer_canonical_abort.is_some());
    let invalid_close_challenge = proof
        .observer_challenges
        .iter()
        .find(|challenge| challenge.kind == AsymptoteObserverChallengeKind::InvalidCanonicalClose)
        .expect("invalid close challenge inserted");
    assert_eq!(
        invalid_close_challenge.canonical_close.as_ref(),
        Some(&invalid_close)
    );
    assert_eq!(artifacts.canonical_close, None);
    assert!(artifacts.canonical_abort.is_some());
}

#[tokio::test]
async fn publish_canonical_observer_abort_artifacts_enqueues_transcript_challenge_and_abort() {
    let assignment = ioi_types::app::AsymptoteObserverAssignment {
        epoch: 9,
        producer_account_id: AccountId([21u8; 32]),
        height: 11,
        view: 4,
        round: 0,
        observer_account_id: AccountId([22u8; 32]),
    };
    let observation_request = ioi_types::app::AsymptoteObserverObservationRequest {
        epoch: 9,
        assignment: assignment.clone(),
        block_hash: [23u8; 32],
        guardian_manifest_hash: [24u8; 32],
        guardian_decision_hash: [25u8; 32],
        guardian_counter: 26,
        guardian_trace_hash: [27u8; 32],
        guardian_measurement_root: [28u8; 32],
        guardian_checkpoint_root: [29u8; 32],
    };
    let transcript = AsymptoteObserverTranscript {
        statement: AsymptoteObserverStatement {
            epoch: 9,
            assignment: assignment.clone(),
            block_hash: [23u8; 32],
            guardian_manifest_hash: [24u8; 32],
            guardian_decision_hash: [25u8; 32],
            guardian_counter: 26,
            guardian_trace_hash: [27u8; 32],
            guardian_measurement_root: [28u8; 32],
            guardian_checkpoint_root: [29u8; 32],
            verdict: ioi_types::app::AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [30u8; 32],
        },
        guardian_certificate: sample_block_header()
            .guardian_certificate
            .expect("sample header must carry guardian certificate"),
    };
    let challenge = AsymptoteObserverChallenge {
        challenge_id: [31u8; 32],
        epoch: 9,
        height: 11,
        view: 4,
        kind: ioi_types::app::AsymptoteObserverChallengeKind::TranscriptMismatch,
        challenger_account_id: AccountId([32u8; 32]),
        assignment: Some(assignment.clone()),
        observation_request: Some(observation_request),
        transcript: Some(transcript.clone()),
        canonical_close: None,
        evidence_hash: [33u8; 32],
        details: "observer recovered a malformed request".to_string(),
    };
    let assignments_hash =
        canonical_asymptote_observer_assignments_hash(&[assignment]).expect("assignment hash");
    let transcripts_root = canonical_asymptote_observer_transcripts_hash(&[transcript.clone()])
        .expect("transcript root");
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&[challenge.clone()]).expect("challenge root");
    let artifacts = CanonicalObserverPublicationArtifacts {
        transcripts: vec![transcript],
        challenges: vec![challenge],
        transcript_commitment: AsymptoteObserverTranscriptCommitment {
            epoch: 9,
            height: 11,
            view: 4,
            assignments_hash,
            transcripts_root,
            transcript_count: 1,
        },
        challenge_commitment: AsymptoteObserverChallengeCommitment {
            epoch: 9,
            height: 11,
            view: 4,
            challenges_root,
            challenge_count: 1,
        },
        canonical_close: None,
        canonical_abort: Some(AsymptoteObserverCanonicalAbort {
            epoch: 9,
            height: 11,
            view: 4,
            assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_700_000_000_500,
        }),
    };
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(TestWorkloadClient),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_canonical_observer_artifacts(&publisher, &artifacts)
        .await
        .expect("artifact publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 5);

    let mut published_bundle = None;
    let methods = selected
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_canonical_order_artifact_bundle@v1" {
                        published_bundle = Some(
                            codec::from_bytes_canonical::<CanonicalOrderPublicationBundle>(&params)
                                .expect("decode published canonical-order bundle"),
                        );
                    }
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec![
            "publish_asymptote_observer_transcript@v1".to_string(),
            "publish_asymptote_observer_transcript_commitment@v1".to_string(),
            "report_asymptote_observer_challenge@v1".to_string(),
            "publish_asymptote_observer_challenge_commitment@v1".to_string(),
            "publish_asymptote_observer_canonical_abort@v1".to_string(),
        ]
    );

    for _ in 0..5 {
        consensus_kick_rx
            .try_recv()
            .expect("publication should kick consensus for each enqueued tx");
    }
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "expected exactly one kick per published artifact tx"
    );
}

#[tokio::test]
async fn publish_canonical_order_artifacts_enqueues_bulletin_surface_and_certificate() {
    let base_header = sample_block_header();
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([41u8; 32]),
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
            account_id: AccountId([42u8; 32]),
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
        ioi_types::app::canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
            .expect("canonicalized transactions");
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().expect("tx hash"))
        .collect();

    let mut header = base_header;
    header.transactions_root = ioi_types::app::canonical_transaction_root_from_hashes(&tx_hashes)
        .expect("transactions root");
    header.canonical_order_certificate = Some(
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .expect("build committed-surface certificate"),
    );

    let artifacts = build_canonical_order_publication_artifacts(&header, &ordered_transactions)
        .expect("build publication artifacts");
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(TestWorkloadClient),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_canonical_order_artifacts(&publisher, &artifacts)
        .await
        .expect("artifact publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 1);

    let mut published_bundle = None;
    let methods = selected
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_canonical_order_artifact_bundle@v1" {
                        published_bundle = Some(
                            codec::from_bytes_canonical::<CanonicalOrderPublicationBundle>(&params)
                                .expect("decode published canonical-order bundle"),
                        );
                    }
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec!["publish_aft_canonical_order_artifact_bundle@v1".to_string()]
    );
    let published_bundle = published_bundle.expect("published bundle captured");
    assert_eq!(
        published_bundle
            .bulletin_retrievability_profile
            .bulletin_commitment_hash,
        published_bundle
            .bulletin_availability_certificate
            .bulletin_commitment_hash
    );
    assert_eq!(
        published_bundle.bulletin_shard_manifest.entry_count,
        published_bundle.bulletin_commitment.entry_count
    );
    assert_eq!(
        published_bundle
            .bulletin_custody_receipt
            .bulletin_shard_manifest_hash,
        ioi_types::app::canonical_bulletin_shard_manifest_hash(
            &published_bundle.bulletin_shard_manifest,
        )
        .expect("hash published shard manifest")
    );

    for _ in 0..1 {
        consensus_kick_rx
            .try_recv()
            .expect("publication should kick consensus for each enqueued tx");
    }
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "expected exactly one kick per published artifact tx"
    );
}

#[tokio::test]
async fn publish_canonical_order_abort_enqueues_abort_tx() {
    let header = sample_block_header();
    let artifacts = build_canonical_order_publication_artifacts(&header, &[])
        .expect("build publication artifacts");
    assert!(artifacts.bundle.is_none());
    let abort = artifacts
        .canonical_abort
        .as_ref()
        .expect("missing certificate must derive ordering abort");
    assert_eq!(abort.height, header.height);

    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(TestWorkloadClient),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_canonical_order_artifacts(&publisher, &artifacts)
        .await
        .expect("abort publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 1);

    let methods = selected
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id, method, ..
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec!["publish_aft_canonical_order_abort@v1".to_string()]
    );
    consensus_kick_rx
        .try_recv()
        .expect("abort publication should kick consensus");
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "expected exactly one kick for the ordering abort publication"
    );
}

