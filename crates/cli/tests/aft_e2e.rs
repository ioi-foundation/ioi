// Path: crates/cli/tests/aft_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use agentgres::consequence::{
    ConsequenceReceiptV1, ConsequenceStateV1, DurablePqAtomicRegisterV1, ExternalResourceV1,
};
use anyhow::Result;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_cli::aft_quv_ceremony::{install_signed_handoff, sign_handoff_draft};
use ioi_cli::testing::backend::ProcessBackend;
use ioi_cli::testing::{
    assert_log_contains, build_test_artifacts, rpc, wait_for, wait_for_height, TestCluster,
};
use ioi_consensus::aft::query_unanimity::{
    quv_candidate_authority_signing_bytes, quv_handoff_domain_id, quv_policy_root,
    validate_quv_handoff_candidate,
};
use ioi_types::app::consensus::{ExternalizationModeV1, GuaranteeRequirementsV1};
use ioi_types::{
    app::{
        account_id_from_key_material, conflict_domain_id_commitment, AccountId, ActiveKeyRecord,
        BlockTimingParams, BlockTimingRuntime, ChainTransaction, EffectAuthorizationModeV1,
        EffectFenceV1, EffectManifestV1, EffectManifestVersionV1, EffectResourceKeyV1,
        QuvAcceptedAuditEvidenceV0, QuvAuthorityModeV0, QuvCandidateV0,
        QuvConfigurationHandoffEnvelopeV0, QuvSlotV0, ReconciliationPolicyV1, SignHeader,
        SignatureProof, SignatureSuite, SystemPayload, SystemTransaction, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1, AFT_EFFECT_REGISTRY_SERVICE_ID,
        REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD,
    },
    codec,
    config::{AftQuvDomainPolicyV0, AftSafetyMode, InitialServiceConfig},
    service_configs::MigrationConfig,
};
use std::collections::HashSet;
use std::ffi::OsString;
use std::time::{Duration, Instant};

static AFT_E2E_ENV_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

struct ScopedEnv {
    prior: Vec<(&'static str, Option<OsString>)>,
}

impl ScopedEnv {
    fn set(entries: &[(&'static str, &'static str)]) -> Self {
        let prior = entries
            .iter()
            .map(|(key, value)| {
                let old = std::env::var_os(key);
                std::env::set_var(key, value);
                (*key, old)
            })
            .collect();
        Self { prior }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for (key, value) in self.prior.drain(..).rev() {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

async fn aft_hash_async_metrics(metrics_addr: &str) -> Result<String> {
    let response = reqwest::get(format!("http://{metrics_addr}/metrics")).await?;
    Ok(response.error_for_status()?.text().await?)
}

async fn observed_block_tip(rpc_addr: &str, floor: u64) -> Result<u64> {
    let mut tip = floor;
    // Queries are substantially faster than the one-second test cadence, so
    // the first missing successor is a stable snapshot for this restart gate.
    // The cap keeps a malformed server from making the diagnostic unbounded.
    for height in floor.saturating_add(1)..=floor.saturating_add(1_000) {
        if rpc::get_block_by_height_resilient(rpc_addr, height)
            .await?
            .is_none()
        {
            return Ok(tip);
        }
        tip = height;
    }
    Err(anyhow::anyhow!(
        "could not bound the observed block tip above height {floor}"
    ))
}

fn signed_system_transaction(
    keypair: &libp2p::identity::Keypair,
    payload: SystemPayload,
    nonce: u64,
    chain_id: ioi_types::app::ChainId,
) -> Result<ChainTransaction> {
    let public_key = keypair.public().encode_protobuf();
    let mut transaction = SystemTransaction {
        header: SignHeader {
            account_id: AccountId(account_id_from_key_material(
                SignatureSuite::ED25519,
                &public_key,
            )?),
            nonce,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };
    let signing_bytes = transaction.to_sign_bytes().map_err(anyhow::Error::msg)?;
    transaction.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: keypair.sign(&signing_bytes)?,
    };
    Ok(ChainTransaction::System(Box::new(transaction)))
}

fn m16q_effect_manifest(
    effect_id: &str,
    resource_id: &str,
    conflict_domain_id: &str,
    conflict_slot: u64,
    policy_root: [u8; 32],
    configuration_root: [u8; 32],
    endpoint: &ioi_crypto::sign::dilithium::MldsaKeyPair,
    discriminator: u8,
) -> Result<EffectManifestV1> {
    let mut manifest = EffectManifestV1 {
        schema_version: EffectManifestVersionV1::V1,
        effect_id: effect_id.into(),
        resource_id: resource_id.into(),
        conflict_domain_id: conflict_domain_id.into(),
        conflict_slot,
        authorization_mode: EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
        online_authorization_policy_root: Some(policy_root),
        read_set: vec![EffectResourceKeyV1 {
            key: format!("m16q/read/{discriminator}"),
            predecessor: Some([discriminator; 32]),
        }],
        write_set: vec![EffectResourceKeyV1 {
            key: format!("m16q/write/{discriminator}"),
            predecessor: None,
        }],
        idempotency_key: "pending".into(),
        request_root: [discriminator.wrapping_add(1); 32],
        predecessor_root: [discriminator.wrapping_add(2); 32],
        intent_root: [discriminator.wrapping_add(3); 32],
        expected_outcome_root: [discriminator.wrapping_add(4); 32],
        resource_profile: DurablePqAtomicRegisterV1::profile_for(endpoint)?,
        required_guarantees: GuaranteeRequirementsV1 {
            require_consensus_pq: true,
            require_externalization_pq: true,
            minimum_externalization: Some(ExternalizationModeV1::IdempotencyRegister),
            require_at_most_once: true,
            ..Default::default()
        },
        fence: EffectFenceV1::ProtocolHeight {
            configuration_hash: configuration_root,
            minimum_height: 1,
            maximum_height: 10_000,
        },
        reconciliation: ReconciliationPolicyV1::LookupByIdempotencyKey {
            maximum_observations: 3,
        },
        irreversible: true,
    };
    manifest.idempotency_key = manifest.query_unanimity_idempotency_key()?;
    manifest.validate()?;
    Ok(manifest)
}

fn m16q_candidate(
    manifest: &EffectManifestV1,
    network_id: [u8; 32],
    configuration_root: [u8; 32],
    policy_root: [u8; 32],
    domain_id: [u8; 32],
    authorizer: AccountId,
    endpoint: &ioi_crypto::sign::dilithium::MldsaKeyPair,
) -> Result<QuvCandidateV0> {
    let mut candidate = QuvCandidateV0 {
        slot: QuvSlotV0 {
            network_id,
            configuration_root,
            policy_root,
            domain_id,
            slot: manifest.conflict_slot,
            predecessor: ioi_crypto::algorithms::hash::sha256(
                b"ioi/aft/m16q/initial-predecessor/v1",
            )?,
            authority_mode: QuvAuthorityModeV0::Unowned,
        },
        payload_hash: manifest.commitment()?,
        authorizer,
        authority_signature: Vec::new(),
    };
    candidate.authority_signature = endpoint
        .sign(&quv_candidate_authority_signing_bytes(&candidate)?)?
        .to_bytes();
    Ok(candidate)
}

fn require_executed_nonportable_quv_receipt(
    response: &ioi_ipc::public::ExecuteAftQuvEffectResponse,
) -> Result<u64> {
    if response.portable_final_receipt {
        return Err(anyhow::anyhow!(
            "online QUV execution mislabeled its consequence audit as portable finality"
        ));
    }
    let receipt: ConsequenceReceiptV1 = serde_json::from_slice(&response.consequence_receipt_jcs)?;
    if serde_jcs::to_vec(&receipt)? != response.consequence_receipt_jcs {
        return Err(anyhow::anyhow!(
            "QUV consequence receipt is not canonical JCS"
        ));
    }
    receipt.validate()?;
    if !matches!(receipt.state, ConsequenceStateV1::Executed { .. }) {
        return Err(anyhow::anyhow!(
            "QUV consequence did not reach the Executed phase"
        ));
    }
    let Some(audit) = receipt.online_authorization_audit.as_ref() else {
        return Err(anyhow::anyhow!(
            "executed consequence omitted its nonportable live QUV audit"
        ));
    };
    if audit.portable_final_receipt || audit.profile != "aft_quv_v0" {
        return Err(anyhow::anyhow!(
            "executed consequence omitted its nonportable live QUV audit"
        ));
    }
    let evidence: QuvAcceptedAuditEvidenceV0 =
        codec::from_bytes_canonical(&audit.protocol_evidence).map_err(anyhow::Error::msg)?;
    if evidence.valid_reply_elapsed_millis.len() != evidence.valid_replies.len() {
        return Err(anyhow::anyhow!(
            "QUV audit reply timings do not align with valid replies"
        ));
    }
    evidence
        .valid_reply_elapsed_millis
        .iter()
        .copied()
        .max()
        .ok_or_else(|| anyhow::anyhow!("QUV audit contains no valid reply timing"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_aft_leader_rotation() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    println!("--- Running Aft deterministic Leader Rotation E2E Test ---");
    build_test_artifacts();

    // 1. Setup a 3-node cluster
    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |builder, keys| {
            let mut validators = Vec::new();
            for key in keys {
                let account_id = builder.add_identity(key);
                let pk = key.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::ED25519, &pk).unwrap();

                validators.push(ValidatorV1 {
                    account_id,
                    weight: 1, // Equal weight for round-robin
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: hash,
                        since_height: 0,
                    },
                });
            }
            // Deterministic sort for stable leader schedule
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: validators.len() as u128,
                    validators,
                },
                next: None,
            };
            builder.set_validators(&vs);

            // Fast blocks for testing
            let timing_params = BlockTimingParams {
                base_interval_secs: 1,
                min_interval_secs: 1,
                max_interval_secs: 5,
                target_gas_per_block: 1_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: timing_params.base_interval_secs,
                ..Default::default()
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        })
        .build()
        .await?;

    // [FIX] Spawn log printers for debugging - Handle closed channels gracefully
    for (i, guard) in cluster.validators.iter().enumerate() {
        let (mut orch_logs, mut work_logs, _) = guard.validator().subscribe_logs();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                     res = orch_logs.recv() => {
                        match res {
                            Ok(line) => println!("[Node {} ORCH] {}", i, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                     }
                     res = work_logs.recv() => {
                        match res {
                            Ok(line) => println!("[Node {} WORK] {}", i, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                     }
                }
            }
        });
    }

    let rpc_addr = &cluster.validators[0].validator().rpc_addr;

    let test_logic = async {
        // 2. Wait for chain progression
        let target_height = 6;
        println!("Waiting for height {}...", target_height);
        wait_for_height(rpc_addr, target_height, Duration::from_secs(30)).await?;

        // 3. Analyze Blocks
        let mut producers = HashSet::new();
        let mut last_height = 0;

        for h in 1..=target_height {
            // [FIX] Add explicit retry loop with logging for the test
            let mut block = None;
            for _ in 0..10 {
                match rpc::get_block_by_height_resilient(rpc_addr, h).await {
                    Ok(Some(b)) => {
                        block = Some(b);
                        break;
                    }
                    Ok(None) => {
                        println!("Block {} not found yet, retrying...", h);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        println!("RPC error for block {}: {}, retrying...", h, e);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            let block =
                block.ok_or_else(|| anyhow::anyhow!("Block {} not found after retries", h))?;

            println!(
                "Block #{}: Producer 0x{}, View {}",
                h,
                hex::encode(&block.header.producer_account_id.0[0..4]),
                block.header.view
            );

            // Verify height continuity
            if block.header.height != last_height + 1 {
                return Err(anyhow::anyhow!("Height gap detected"));
            }
            last_height = block.header.height;

            producers.insert(block.header.producer_account_id);
        }

        // 4. Verify Rotation
        // With 3 validators and 6 blocks, we expect at least 2 unique producers (ideally 3).
        // If only 1 produced all blocks, round-robin failed.
        if producers.len() < 2 {
            return Err(anyhow::anyhow!(
                "Leader rotation failed: observed {:?} unique producers out of 3 validators",
                producers.len()
            ));
        }

        println!("--- Aft deterministic Leader Rotation Test Passed ---");
        Ok(())
    };

    let result = test_logic.await;

    // Always shutdown
    if let Err(e) = cluster.shutdown().await {
        eprintln!("Error shutting down cluster: {}", e);
    }

    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_quv_disjoint_successors_install_live_handoff_before_activation() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let fixture = tempfile::tempdir()?;
    let source_path = fixture.path().join("handoff.scale");
    let draft_path = fixture.path().join("handoff.scale.draft");
    let source_path_string = source_path.to_string_lossy().into_owned();
    let activation_height = 3;
    let delta_rt_millis = 30_000;
    let continuation_millis = 5_000;
    let effect_conflict_domain_id = "domain://aft-e2e/quv-effect";
    let effect_domain =
        conflict_domain_id_commitment(effect_conflict_domain_id).map_err(anyhow::Error::msg)?;
    let effect_delta_rt_millis = 5_000;
    let effect_continuation_millis = 5_000;
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_BUILD_PROFILE", "release"),
        ("IOI_TEST_VALIDATOR_LAUNCH_CONCURRENCY", "2"),
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        // The cluster intentionally contains four pre-active processes whose
        // canonical height remains zero until their own live QUV install.
        // The test below waits for the canonical handoff draft and then checks
        // every successor boundary explicitly, so the generic all-process
        // shared-tip predicate is inapplicable here.
        ("IOI_TEST_SKIP_SHARED_TIP_WAIT", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS", "180"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "1000"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    let mut cluster = TestCluster::builder()
        // Both the old live-ordering configuration and its fully disjoint
        // successor retain the normative n=3f+1 geometry. QUV changes the
        // effect-authorization/handoff theorem; it does not launder an
        // undersized ordering committee into a qualified BFT profile.
        .with_validators(8)
        .with_consensus_type("Aft")
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_state_tree("IAVL")
        .with_chain_id(0xA19)
        .with_quv_handoff_profile(
            4,
            activation_height,
            delta_rt_millis,
            continuation_millis,
            source_path_string,
        )
        .with_quv_domain_policy(AftQuvDomainPolicyV0 {
            domain_id: effect_domain,
            authority_mode: QuvAuthorityModeV0::Unowned,
            owner: None,
            delta_rt_millis: effect_delta_rt_millis,
            qualified_delta_rt_envelope_millis: 4_000,
            qualified_max_configured_members: 4,
            continuation_millis: effect_continuation_millis,
        })
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 0xA19,
            grace_period_blocks: 0,
            accept_staged_during_grace: false,
            allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
            allow_downgrade: false,
        }))
        .build()
        .await?;

    let run = async {
        let mut keyed = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(index, guard)| {
                let keypair = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("QUV fixture must retain every ML-DSA validator key");
                let public = keypair.public_key().to_bytes();
                let account = AccountId(account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &public,
                )?);
                Ok((account, index, public))
            })
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by_key(|(account, _, _)| *account);

        let old = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 4,
            validators: keyed[..4]
                .iter()
                .map(|(account, _, _)| ValidatorV1 {
                    account_id: *account,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: account.0,
                        since_height: 0,
                    },
                })
                .collect(),
        };
        let successor = ValidatorSetV1 {
            effective_from_height: activation_height,
            total_weight: 4,
            validators: keyed[4..]
                .iter()
                .map(|(account, _, _)| ValidatorV1 {
                    account_id: *account,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: account.0,
                        since_height: activation_height,
                    },
                })
                .collect(),
        };
        let old_root =
            ioi_types::app::canonical_validator_set_hash(&old).map_err(anyhow::Error::msg)?;
        let successor_root =
            ioi_types::app::canonical_validator_set_hash(&successor).map_err(anyhow::Error::msg)?;
        let network_id = ioi_crypto::algorithms::hash::sha256(cluster.genesis_content.as_bytes())?;
        let domain_id =
            quv_handoff_domain_id(network_id, old_root, successor_root, activation_height)?;
        let policy_root = quv_policy_root(
            domain_id,
            QuvAuthorityModeV0::Owned,
            Some(keyed[0].0),
            delta_rt_millis,
            continuation_millis,
        )?;

        let mut successor_logs = keyed[4..]
            .iter()
            .map(|(_, index, _)| {
                let (orchestration, _, _) = cluster.validators[*index].validator().subscribe_logs();
                (*index, orchestration)
            })
            .collect::<Vec<_>>();
        let envelope = wait_for(
            "the exact unsigned QUV handoff owner-ceremony draft",
            Duration::from_millis(250),
            Duration::from_secs(90),
            || {
                let draft_path = draft_path.clone();
                async move {
                    let Ok(bytes) = std::fs::read(&draft_path) else {
                        return Ok(None);
                    };
                    match codec::from_bytes_canonical::<QuvConfigurationHandoffEnvelopeV0>(&bytes) {
                        Ok(envelope) => Ok(Some(envelope)),
                        Err(_) => Ok(None),
                    }
                }
            },
        )
        .await?;
        let drafted_successor_root =
            ioi_types::app::canonical_validator_set_hash(&envelope.handoff.successor_set)
                .map_err(anyhow::Error::msg)?;
        if envelope.handoff.network_id != network_id
            || envelope.handoff.old_configuration_root != old_root
            || drafted_successor_root != successor_root
            || envelope.handoff.activation_height != activation_height
            || envelope.handoff.state_height != activation_height - 1
            || envelope.handoff.boundary_qc.height != envelope.handoff.state_height
            || envelope.handoff.boundary_qc.block_hash != envelope.handoff.state_block_hash
            || envelope.handoff.boundary_qc.signatures.len() != 3
            || envelope.candidate.slot.domain_id != domain_id
            || envelope.candidate.slot.policy_root != policy_root
            || envelope.candidate.authorizer != keyed[0].0
            || !envelope.candidate.authority_signature.is_empty()
        {
            return Err(anyhow::anyhow!(
                "pre-publication QUV handoff draft differs from the rooted ceremony"
            ));
        }
        validate_quv_handoff_candidate(&envelope.candidate, &envelope.handoff)?;

        // Restart one successor before any signed source or local install
        // exists. Its next attempt is armed to exit in the precise recoverable
        // window after the new handoff state is durable but before the
        // separately rooted anchor advances.
        let interrupted_index = keyed[7].1;
        let interrupted_account = keyed[7].0;
        let interrupted_state = cluster.validators[interrupted_index]
            .validator()
            .state_dir()
            .join("aft-pq-outbox")
            .join(hex::encode(old_root))
            .join(hex::encode(interrupted_account.as_ref()))
            .join("quv-handoff-v0.scale");
        let preinstall_state = wait_for(
            "the interrupted successor's empty durable handoff state",
            Duration::from_millis(50),
            Duration::from_secs(30),
            || {
                let path = interrupted_state.clone();
                async move { Ok(std::fs::read(path).ok()) }
            },
        )
        .await?;
        let crash_marker = fixture.path().join("handoff-state-durable.marker");
        cluster.validators[interrupted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[interrupted_index]
            .validator_mut()
            .set_orchestration_restart_env(
                "IOI_TESTING_AFT_QUV_HANDOFF_CRASH_AFTER_STATE_MARKER",
                crash_marker.to_string_lossy().as_ref(),
            )?;
        cluster.validators[interrupted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        wait_for(
            "the pre-install successor restart to expose its RPC without authority",
            Duration::from_millis(100),
            Duration::from_secs(30),
            || {
                let rpc_addr = cluster.validators[interrupted_index]
                    .validator()
                    .rpc_addr
                    .clone();
                async move { Ok(rpc::get_status(&rpc_addr).await.ok().map(|_| ())) }
            },
        )
        .await?;
        let owner_key_path = cluster.validators[keyed[0].1]
            .validator()
            .state_dir()
            .join("pqc_key.json");
        let signed_path = source_path.with_extension("signed.scale");
        let signed_audit = sign_handoff_draft(
            &draft_path,
            &owner_key_path,
            &signed_path,
            false,
        )?;
        if signed_audit.portable_final_receipt
            || signed_audit.process_local_authorization_present
            || !signed_audit.owner_signature_present
        {
            return Err(anyhow::anyhow!(
                "operator ceremony mislabeled replayable handoff input as online authority"
            ));
        }
        install_signed_handoff(
            &signed_path,
            &owner_key_path,
            &source_path,
            false,
        )?;

        wait_for(
            "the QUV handoff state-durable/anchor-pending crash marker",
            Duration::from_millis(25),
            Duration::from_secs(90),
            || {
                let marker = crash_marker.clone();
                async move { Ok(marker.is_file().then_some(())) }
            },
        )
        .await?;
        // Clear the exited child handle, then restart from the state that is
        // exactly one generation ahead of its valid old anchor. Recovery may
        // complete only that transition.
        cluster.validators[interrupted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[interrupted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;

        let first_successor_rpc = cluster.validators[keyed[4].1].validator().rpc_addr.clone();
        let synchronized_boundary = wait_for(
            "the first successor's synchronized QUV boundary block",
            Duration::from_millis(250),
            Duration::from_secs(90),
            || {
                let rpc_addr = first_successor_rpc.clone();
                async move {
                    rpc::get_block_by_height_resilient(&rpc_addr, activation_height - 1).await
                }
            },
        )
        .await?;
        let synchronized_hash: [u8; 32] = synchronized_boundary
            .header
            .hash()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("synchronized QUV block hash is not 32 bytes"))?;
        if synchronized_boundary.header.height != envelope.handoff.state_height
            || synchronized_hash != envelope.handoff.state_block_hash
            || synchronized_boundary.header.state_root.0 != envelope.handoff.state_root
        {
            let mut observed = Vec::new();
            for (index, guard) in cluster.validators.iter().enumerate() {
                let role = if keyed[..4]
                    .iter()
                    .any(|(_, member_index, _)| *member_index == index)
                {
                    "old"
                } else {
                    "successor"
                };
                match rpc::get_block_by_height_resilient(
                    &guard.validator().rpc_addr,
                    activation_height - 1,
                )
                .await
                {
                    Ok(Some(block)) => observed.push(format!(
                        "node{index}:{role}:hash={}:root={}:sig={}:view={}:producer={}",
                        hex::encode(block.header.hash()?),
                        hex::encode(&block.header.state_root.0),
                        block.header.signature.len(),
                        block.header.view,
                        hex::encode(block.header.producer_account_id.as_ref()),
                    )),
                    Ok(None) => observed.push(format!("node{index}:{role}:missing")),
                    Err(error) => observed.push(format!("node{index}:{role}:rpc-error({error:#})")),
                }
            }
            return Err(anyhow::anyhow!(
                "successor synchronized a different QUV boundary: height={}/{} hash={}/{} state_root={}/{} signature_len={} guardian={} seal={}; all_nodes=[{}]",
                synchronized_boundary.header.height,
                envelope.handoff.state_height,
                hex::encode(synchronized_hash),
                hex::encode(envelope.handoff.state_block_hash),
                hex::encode(&synchronized_boundary.header.state_root.0),
                hex::encode(&envelope.handoff.state_root),
                synchronized_boundary.header.signature.len(),
                synchronized_boundary.header.guardian_certificate.is_some(),
                synchronized_boundary.header.sealed_finality_proof.is_some(),
                observed.join(", "),
            ));
        }

        for (index, log) in &mut successor_logs {
            assert_log_contains(
                &format!("QUV successor node {index}"),
                log,
                if *index == interrupted_index {
                    "Recovered QUV successor authority from its durable local install gate"
                } else {
                    "Activated successor from its local live old-root QUV install"
                },
            )
            .await?;
        }
        // Retired old-root processes have no post-activation role. Stop them
        // before measuring successor liveness so an eight-process fixture on
        // a four-core qualification host does not turn retired busy work into
        // an undeclared scheduler adversary. This also strengthens the
        // handoff check: successor progress must not depend on old members.
        for (_, index, _) in &keyed[..4] {
            cluster.validators[*index]
                .validator_mut()
                .kill_orchestration()
                .await?;
        }
        // Only the rooted successor set is required to carry post-handoff
        // ordering. Retired members are not implicitly observers: that would
        // give their retired validator credentials an undocumented role after
        // the network is reconfigured. Their fail-closed restart behavior is
        // asserted below; a future observer role needs separate credentials.
        for (_, index, _) in &keyed[4..] {
            let index = *index;
            let guard = &cluster.validators[index];
            if let Err(error) = wait_for_height(
                &guard.validator().rpc_addr,
                activation_height + 2,
                Duration::from_secs(180),
            )
            .await
            {
                let mut status = Vec::new();
                for (peer_index, peer) in cluster.validators.iter().enumerate() {
                    match rpc::get_status(&peer.validator().rpc_addr).await {
                        Ok(observed) => status.push(format!("node{peer_index}={}", observed.height)),
                        Err(peer_error) => {
                            status.push(format!("node{peer_index}=rpc-error({peer_error:#})"))
                        }
                    }
                }
                return Err(anyhow::anyhow!(
                    "successor node {index} did not observe post-QUV height {}: {error:#}; status=[{}]",
                    activation_height + 2,
                    status.join(", ")
                ));
            }
            let block = rpc::get_block_by_height_resilient(
                &guard.validator().rpc_addr,
                activation_height + 1,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("QUV successor block was not observable"))?;
            if !successor
                .validators
                .iter()
                .any(|member| member.account_id == block.header.producer_account_id)
            {
                return Err(anyhow::anyhow!(
                    "post-handoff block was not produced by the installed successor set"
                ));
            }
        }

        // Restart a live successor authority process while leaving its
        // workload/state process intact. Recovery must consume the existing
        // rollback-anchored install gate; it may not re-run QUV against an
        // expired old root or infer authority from the source bytes.
        let restarted_index = keyed[4].1;
        let restarted_rpc = cluster.validators[restarted_index]
            .validator()
            .rpc_addr
            .clone();
        let before_restart = observed_block_tip(&restarted_rpc, activation_height + 2).await?;
        let (mut restarted_log, _, _) = cluster.validators[restarted_index]
            .validator()
            .subscribe_logs();
        cluster.validators[restarted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[restarted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("restarted QUV successor node {restarted_index}"),
            &mut restarted_log,
            "Recovered QUV successor authority from its durable local install gate",
        )
        .await?;
        let post_restart_height = before_restart.saturating_add(2);
        wait_for(
            "two new canonical QUV blocks after successor restart",
            Duration::from_millis(250),
            Duration::from_secs(240),
            || {
                let rpc_addr = restarted_rpc.clone();
                async move {
                    rpc::get_block_by_height_resilient(&rpc_addr, post_restart_height).await
                }
            },
        )
        .await?;

        // Admit an irreversible effect through the real workload, bind its
        // manifest root into the block's Agentgres record, then ask one
        // relying executor to run fresh QUV against every active successor
        // and immediately continue into the PQ atomic T10 resource. The RPC
        // response is consequence audit/state only, never bearer authority.
        let executor_account = keyed[4].0;
        let executor_key = cluster.validators[restarted_index]
            .validator()
            .pqc_keypair
            .as_ref()
            .expect("QUV executor must retain its ML-DSA key")
            .clone();
        let effect_policy_root = quv_policy_root(
            effect_domain,
            QuvAuthorityModeV0::Unowned,
            None,
            effect_delta_rt_millis,
            effect_continuation_millis,
        )?;
        let mut manifest = EffectManifestV1 {
            schema_version: EffectManifestVersionV1::V1,
            effect_id: "effect-quv-e2e-1".into(),
            resource_id: "resource://aft-e2e/pq-register".into(),
            conflict_domain_id: effect_conflict_domain_id.into(),
            conflict_slot: 1,
            authorization_mode: EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
            online_authorization_policy_root: Some(effect_policy_root),
            read_set: vec![EffectResourceKeyV1 {
                key: "account/source".into(),
                predecessor: Some([21; 32]),
            }],
            write_set: vec![EffectResourceKeyV1 {
                key: "settlement/one".into(),
                predecessor: None,
            }],
            idempotency_key: "pending".into(),
            request_root: [22; 32],
            predecessor_root: [23; 32],
            intent_root: [24; 32],
            expected_outcome_root: [25; 32],
            resource_profile: DurablePqAtomicRegisterV1::profile_for(&executor_key)?,
            required_guarantees: GuaranteeRequirementsV1 {
                require_consensus_pq: true,
                require_externalization_pq: true,
                minimum_externalization: Some(ExternalizationModeV1::IdempotencyRegister),
                require_at_most_once: true,
                ..Default::default()
            },
            fence: EffectFenceV1::ProtocolHeight {
                configuration_hash: successor_root,
                minimum_height: activation_height,
                maximum_height: 10_000,
            },
            reconciliation: ReconciliationPolicyV1::LookupByIdempotencyKey {
                maximum_observations: 3,
            },
            irreversible: true,
        };
        manifest.idempotency_key = manifest.query_unanimity_idempotency_key()?;
        manifest.validate()?;
        let registration = signed_system_transaction(
            &cluster.validators[restarted_index].validator().keypair,
            SystemPayload::CallService {
                service_id: AFT_EFFECT_REGISTRY_SERVICE_ID.into(),
                method: REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD.into(),
                params: serde_jcs::to_vec(&manifest)?,
            },
            0,
            0xA19_u32.into(),
        )?;
        rpc::submit_transaction(&restarted_rpc, &registration).await?;

        let mut candidate = QuvCandidateV0 {
            slot: QuvSlotV0 {
                network_id,
                configuration_root: successor_root,
                policy_root: effect_policy_root,
                domain_id: effect_domain,
                slot: manifest.conflict_slot,
                predecessor: ioi_crypto::algorithms::hash::sha256(
                    b"ioi/aft/e2e-effect-initial-predecessor/v1",
                )?,
                authority_mode: QuvAuthorityModeV0::Unowned,
            },
            payload_hash: manifest.commitment()?,
            authorizer: executor_account,
            authority_signature: Vec::new(),
        };
        candidate.authority_signature = executor_key
            .sign(&quv_candidate_authority_signing_bytes(&candidate)?)?
            .to_bytes();
        let response = rpc::execute_aft_quv_effect(
            &restarted_rpc,
            &manifest.effect_id,
            &candidate,
        )
        .await?;
        if response.portable_final_receipt {
            return Err(anyhow::anyhow!(
                "online QUV executor mislabeled consequence audit as portable finality"
            ));
        }
        let receipt: ConsequenceReceiptV1 =
            serde_json::from_slice(&response.consequence_receipt_jcs)?;
        if serde_jcs::to_vec(&receipt)? != response.consequence_receipt_jcs {
            return Err(anyhow::anyhow!(
                "QUV consequence response is not canonical JCS"
            ));
        }
        receipt.validate()?;
        let record = match &receipt.state {
            ConsequenceStateV1::Executed {
                resource_record, ..
            } => resource_record,
            state => {
                return Err(anyhow::anyhow!(
                    "QUV consequence did not reach Executed: {:?}",
                    state.phase()
                ))
            }
        };
        if receipt.online_authorization_audit.as_ref().is_none_or(|audit| {
            audit.portable_final_receipt || audit.profile != "aft_quv_v0"
        }) {
            return Err(anyhow::anyhow!(
                "T10 consequence omitted its nonportable live QUV audit"
            ));
        }
        let resource_root = cluster.validators[restarted_index]
            .validator()
            .state_dir()
            .join("ordering-finality")
            .join("quv-external-resource");
        let mut resource = DurablePqAtomicRegisterV1::open(resource_root, executor_key)?;
        let observed = resource
            .lookup(&manifest.resource_id, &manifest.idempotency_key)
            .map_err(|error| anyhow::anyhow!("resource lookup failed: {error:?}"))?
            .ok_or_else(|| anyhow::anyhow!("T10 resource mutation is absent"))?;
        if observed != *record || !resource.verify_record_evidence(&observed) {
            return Err(anyhow::anyhow!(
                "T10 resource record or its rooted ML-DSA evidence differs"
            ));
        }

        // Source bytes are still replayable input after a successful live
        // install. Replacing even the owner signature cannot borrow the
        // process-local gate created for the original envelope.
        let substituted_index = keyed[5].1;
        let source_bytes = std::fs::read(&source_path)?;
        let mut substituted: QuvConfigurationHandoffEnvelopeV0 =
            codec::from_bytes_canonical(&source_bytes).map_err(anyhow::Error::msg)?;
        substituted.candidate.authority_signature[0] ^= 0x01;
        std::fs::write(
            &source_path,
            codec::to_bytes_canonical(&substituted).map_err(anyhow::Error::msg)?,
        )?;
        let (mut substituted_log, _, _) = cluster.validators[substituted_index]
            .validator()
            .subscribe_logs();
        cluster.validators[substituted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[substituted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("source-substituted QUV successor node {substituted_index}"),
            &mut substituted_log,
            "QUV recovery source has no exact rollback-anchored local install gate",
        )
        .await?;
        std::fs::write(&source_path, source_bytes)?;

        // Once old authority has expired, loss of either side of the durable
        // install pair fails closed. Startup may not rerun QUV retroactively.
        let missing_gate_index = keyed[6].1;
        let missing_gate_account = keyed[6].0;
        let missing_gate_state = cluster.validators[missing_gate_index]
            .validator()
            .state_dir()
            .join("aft-pq-outbox")
            .join(hex::encode(old_root))
            .join(hex::encode(missing_gate_account.as_ref()))
            .join("quv-handoff-v0.scale");
        if !missing_gate_state.is_file() {
            return Err(anyhow::anyhow!(
                "expected installed QUV handoff state at {}",
                missing_gate_state.display()
            ));
        }
        let (mut missing_gate_log, _, _) = cluster.validators[missing_gate_index]
            .validator()
            .subscribe_logs();
        cluster.validators[missing_gate_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        std::fs::remove_file(&missing_gate_state)?;
        cluster.validators[missing_gate_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("missing-gate QUV successor node {missing_gate_index}"),
            &mut missing_gate_log,
            "QUV store and rollback anchor are incomplete",
        )
        .await?;

        // Restoring the captured generation-zero state while retaining the
        // current external anchor is an explicit rollback image, not a crash
        // window. Restart must reject it rather than recreate the live gate.
        let (mut rollback_log, _, _) = cluster.validators[interrupted_index]
            .validator()
            .subscribe_logs();
        cluster.validators[interrupted_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        std::fs::write(&interrupted_state, &preinstall_state)?;
        cluster.validators[interrupted_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("rollback-image QUV successor node {interrupted_index}"),
            &mut rollback_log,
            "QUV store rollback or fork detected",
        )
        .await?;

        // A retired old-root process has no successor vote or proposal
        // identity after restart. Until a separately rooted observer profile
        // exists, it must stop rather than infer membership from its old key.
        let retired_index = keyed[0].1;
        let (mut retired_log, _, _) = cluster.validators[retired_index]
            .validator()
            .subscribe_logs();
        cluster.validators[retired_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[retired_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("retired old-root QUV node {retired_index}"),
            &mut retired_log,
            "local ML-DSA signer belongs to neither the effective set nor the staged QUV successor set",
        )
        .await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;
    let shutdown = cluster.shutdown().await;
    run?;
    shutdown?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_quv_overlapping_member_installs_and_recovers_the_same_live_handoff() -> Result<()>
{
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let fixture = tempfile::tempdir()?;
    let source_path = fixture.path().join("overlap-handoff.scale");
    let draft_path = fixture.path().join("overlap-handoff.scale.draft");
    let activation_height = 3;
    let delta_rt_millis = 30_000;
    let continuation_millis = 5_000;
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_BUILD_PROFILE", "release"),
        ("IOI_TEST_VALIDATOR_LAUNCH_CONCURRENCY", "2"),
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_SKIP_SHARED_TIP_WAIT", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "1000"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    // Four old members, one of which remains, plus three new members. Both
    // configurations therefore retain n=4 and the same ordering geometry.
    let mut cluster = TestCluster::builder()
        .with_validators(7)
        .with_consensus_type("Aft")
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_state_tree("IAVL")
        .with_chain_id(0xA1A)
        .with_quv_handoff_profile(
            4,
            activation_height,
            delta_rt_millis,
            continuation_millis,
            source_path.to_string_lossy(),
        )
        .with_quv_handoff_overlap_count(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 0xA1A,
            grace_period_blocks: 0,
            accept_staged_during_grace: false,
            allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
            allow_downgrade: false,
        }))
        .build()
        .await?;

    let run = async {
        let mut keyed = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(index, guard)| {
                let key = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("overlap fixture requires ML-DSA identities");
                let public = key.public_key().to_bytes();
                let account = AccountId(account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &public,
                )?);
                Ok((account, index))
            })
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by_key(|(account, _)| *account);

        let member = |(account, _): &(AccountId, usize), since_height| ValidatorV1 {
            account_id: *account,
            weight: 1,
            consensus_key: ActiveKeyRecord {
                suite: SignatureSuite::ML_DSA_44,
                public_key_hash: account.0,
                since_height,
            },
        };
        let old = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 4,
            validators: keyed[..4].iter().map(|entry| member(entry, 0)).collect(),
        };
        let mut successor_members = vec![member(&keyed[0], 0)];
        successor_members.extend(
            keyed[4..]
                .iter()
                .map(|entry| member(entry, activation_height)),
        );
        successor_members.sort_by_key(|entry| entry.account_id);
        let successor = ValidatorSetV1 {
            effective_from_height: activation_height,
            total_weight: 4,
            validators: successor_members,
        };
        let old_root = ioi_types::app::canonical_validator_set_hash(&old)
            .map_err(anyhow::Error::msg)?;
        let successor_root = ioi_types::app::canonical_validator_set_hash(&successor)
            .map_err(anyhow::Error::msg)?;
        let network_id = ioi_crypto::algorithms::hash::sha256(cluster.genesis_content.as_bytes())?;
        let domain_id =
            quv_handoff_domain_id(network_id, old_root, successor_root, activation_height)?;
        let policy_root = quv_policy_root(
            domain_id,
            QuvAuthorityModeV0::Owned,
            Some(keyed[0].0),
            delta_rt_millis,
            continuation_millis,
        )?;

        let mut successor_logs = successor
            .validators
            .iter()
            .map(|member| {
                let index = keyed
                    .iter()
                    .find(|(account, _)| account == &member.account_id)
                    .expect("successor process exists")
                    .1;
                let (log, _, _) = cluster.validators[index].validator().subscribe_logs();
                (index, log)
            })
            .collect::<Vec<_>>();
        let envelope = wait_for(
            "the overlapping QUV handoff draft",
            Duration::from_millis(250),
            Duration::from_secs(90),
            || {
                let path = draft_path.clone();
                async move {
                    let Ok(bytes) = std::fs::read(path) else {
                        return Ok(None);
                    };
                    Ok(
                        codec::from_bytes_canonical::<QuvConfigurationHandoffEnvelopeV0>(&bytes)
                            .ok(),
                    )
                }
            },
        )
        .await?;
        if envelope.handoff.old_configuration_root != old_root
            || ioi_types::app::canonical_validator_set_hash(&envelope.handoff.successor_set)
                .map_err(anyhow::Error::msg)?
                != successor_root
            || envelope.candidate.slot.domain_id != domain_id
            || envelope.candidate.slot.policy_root != policy_root
            || envelope.candidate.authorizer != keyed[0].0
        {
            return Err(anyhow::anyhow!(
                "overlapping QUV draft differs from its rooted configuration"
            ));
        }
        validate_quv_handoff_candidate(&envelope.candidate, &envelope.handoff)?;
        let owner_key_path = cluster.validators[keyed[0].1]
            .validator()
            .state_dir()
            .join("pqc_key.json");
        let signed_path = source_path.with_extension("signed.scale");
        sign_handoff_draft(
            &draft_path,
            &owner_key_path,
            &signed_path,
            false,
        )?;
        install_signed_handoff(
            &signed_path,
            &owner_key_path,
            &source_path,
            false,
        )?;

        for (index, log) in &mut successor_logs {
            assert_log_contains(
                &format!("overlapping QUV successor node {index}"),
                log,
                "Activated successor from its local live old-root QUV install",
            )
            .await?;
            wait_for_height(
                &cluster.validators[*index].validator().rpc_addr,
                activation_height + 2,
                Duration::from_secs(180),
            )
            .await?;
        }

        // The member common to both roots must have traversed the same live
        // install gate as every new member. Its old membership cannot stand in
        // for QUV, and restart must recover the exact successor-scoped gate.
        let overlap_index = keyed[0].1;
        let overlap_rpc = cluster.validators[overlap_index]
            .validator()
            .rpc_addr
            .clone();
        let before_restart = observed_block_tip(&overlap_rpc, activation_height + 2).await?;
        let (mut overlap_log, _, _) = cluster.validators[overlap_index]
            .validator()
            .subscribe_logs();
        cluster.validators[overlap_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[overlap_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("restarted overlapping QUV member {overlap_index}"),
            &mut overlap_log,
            "Recovered QUV successor authority from its durable local install gate",
        )
        .await?;
        let post_restart_height = before_restart.saturating_add(2);
        wait_for(
            "two new canonical overlapping-root blocks after restart",
            Duration::from_millis(250),
            Duration::from_secs(180),
            || {
                let rpc_addr = overlap_rpc.clone();
                async move {
                    rpc::get_block_by_height_resilient(&rpc_addr, post_restart_height).await
                }
            },
        )
        .await?;

        let retired_index = keyed[1].1;
        let (mut retired_log, _, _) = cluster.validators[retired_index]
            .validator()
            .subscribe_logs();
        cluster.validators[retired_index]
            .validator_mut()
            .kill_orchestration()
            .await?;
        cluster.validators[retired_index]
            .validator_mut()
            .restart_orchestration_process()
            .await?;
        assert_log_contains(
            &format!("retired non-overlapping member {retired_index}"),
            &mut retired_log,
            "local ML-DSA signer belongs to neither the effective set nor the staged QUV successor set",
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let shutdown = cluster.shutdown().await;
    run?;
    shutdown?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();

    const CHAIN_ID: u32 = 0xA20;
    const DELTA_RT_MILLIS: u64 = 5_000;
    const CONTINUATION_MILLIS: u64 = 5_000;
    const CONFLICT_SLOT: u64 = 1;
    let solo_domain_ids = [
        "domain://aft-e2e/m16q/solo-0",
        "domain://aft-e2e/m16q/solo-1",
        "domain://aft-e2e/m16q/solo-2",
        "domain://aft-e2e/m16q/solo-3",
    ];
    let saturation_domain_ids = [
        "domain://aft-e2e/m16q/saturation-0",
        "domain://aft-e2e/m16q/saturation-1",
        "domain://aft-e2e/m16q/saturation-2",
        "domain://aft-e2e/m16q/saturation-3",
    ];
    let conflict_domain_id = "domain://aft-e2e/m16q/conflict";
    let unrelated_domain_id = "domain://aft-e2e/m16q/unrelated";
    let mut policy_domains = solo_domain_ids.iter().copied().collect::<Vec<_>>();
    policy_domains.extend(saturation_domain_ids.iter().copied());
    policy_domains.extend([conflict_domain_id, unrelated_domain_id]);
    let policies = policy_domains
        .iter()
        .map(|domain_id| {
            let domain_id = conflict_domain_id_commitment(domain_id).map_err(anyhow::Error::msg)?;
            Ok(AftQuvDomainPolicyV0 {
                domain_id,
                authority_mode: QuvAuthorityModeV0::Unowned,
                owner: None,
                delta_rt_millis: DELTA_RT_MILLIS,
                qualified_delta_rt_envelope_millis: 4_000,
                qualified_max_configured_members: 4,
                continuation_millis: CONTINUATION_MILLIS,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_BUILD_PROFILE", "release"),
        ("IOI_TEST_VALIDATOR_LAUNCH_CONCURRENCY", "2"),
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS", "180"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "500"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    let mut builder = TestCluster::builder()
        .with_validators(4)
        .with_consensus_type("Aft")
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_pq_consensus_profile()
        .with_state_tree("IAVL")
        .with_chain_id(CHAIN_ID)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: CHAIN_ID,
            grace_period_blocks: 0,
            accept_staged_during_grace: false,
            allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
            allow_downgrade: false,
        }));
    for policy in policies.iter().cloned() {
        builder = builder.with_quv_domain_policy(policy);
    }
    let mut cluster = builder.build().await?;

    let run = async {
        let mut members = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(process_index, guard)| {
                let endpoint = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("M16Q process member must retain its ML-DSA key")
                    .clone();
                let account = AccountId(account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &endpoint.public_key().to_bytes(),
                )?);
                Ok((account, process_index, endpoint))
            })
            .collect::<Result<Vec<_>>>()?;
        members.sort_by_key(|(account, _, _)| *account);
        let active_set = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: members.len() as u128,
            validators: members
                .iter()
                .map(|(account, _, _)| ValidatorV1 {
                    account_id: *account,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: account.0,
                        since_height: 0,
                    },
                })
                .collect(),
        };
        let configuration_root = ioi_types::app::canonical_validator_set_hash(&active_set)
            .map_err(anyhow::Error::msg)?;
        let network_id = ioi_crypto::algorithms::hash::sha256(cluster.genesis_content.as_bytes())?;

        let mut manifests = Vec::new();
        for (member_position, (_, process_index, endpoint)) in members.iter().enumerate() {
            let domain_id = solo_domain_ids[member_position];
            let domain =
                conflict_domain_id_commitment(domain_id).map_err(anyhow::Error::msg)?;
            let policy_root = quv_policy_root(
                domain,
                QuvAuthorityModeV0::Unowned,
                None,
                DELTA_RT_MILLIS,
                CONTINUATION_MILLIS,
            )?;
            manifests.push((
                *process_index,
                domain,
                policy_root,
                m16q_effect_manifest(
                    &format!("effect-m16q-solo-{member_position}"),
                    &format!("resource://aft-e2e/m16q/solo-{member_position}"),
                    domain_id,
                    CONFLICT_SLOT,
                    policy_root,
                    configuration_root,
                    endpoint,
                    10 + member_position as u8,
                )?,
            ));
        }
        let mut saturation_manifests = Vec::new();
        for (member_position, (_, process_index, endpoint)) in members.iter().enumerate() {
            let domain_id = saturation_domain_ids[member_position];
            let domain =
                conflict_domain_id_commitment(domain_id).map_err(anyhow::Error::msg)?;
            let policy_root = quv_policy_root(
                domain,
                QuvAuthorityModeV0::Unowned,
                None,
                DELTA_RT_MILLIS,
                CONTINUATION_MILLIS,
            )?;
            saturation_manifests.push((
                *process_index,
                domain,
                policy_root,
                m16q_effect_manifest(
                    &format!("effect-m16q-saturation-{member_position}"),
                    &format!("resource://aft-e2e/m16q/saturation-{member_position}"),
                    domain_id,
                    CONFLICT_SLOT,
                    policy_root,
                    configuration_root,
                    endpoint,
                    20 + member_position as u8,
                )?,
            ));
        }
        let conflict_domain =
            conflict_domain_id_commitment(conflict_domain_id).map_err(anyhow::Error::msg)?;
        let conflict_policy_root = quv_policy_root(
            conflict_domain,
            QuvAuthorityModeV0::Unowned,
            None,
            DELTA_RT_MILLIS,
            CONTINUATION_MILLIS,
        )?;
        let conflict_a = m16q_effect_manifest(
            "effect-m16q-conflict-a",
            "resource://aft-e2e/m16q/conflict-a",
            conflict_domain_id,
            CONFLICT_SLOT,
            conflict_policy_root,
            configuration_root,
            &members[0].2,
            40,
        )?;
        let conflict_b = m16q_effect_manifest(
            "effect-m16q-conflict-b",
            "resource://aft-e2e/m16q/conflict-b",
            conflict_domain_id,
            CONFLICT_SLOT,
            conflict_policy_root,
            configuration_root,
            &members[1].2,
            41,
        )?;
        let unrelated_domain =
            conflict_domain_id_commitment(unrelated_domain_id).map_err(anyhow::Error::msg)?;
        let unrelated_policy_root = quv_policy_root(
            unrelated_domain,
            QuvAuthorityModeV0::Unowned,
            None,
            DELTA_RT_MILLIS,
            CONTINUATION_MILLIS,
        )?;
        let unrelated = m16q_effect_manifest(
            "effect-m16q-unrelated",
            "resource://aft-e2e/m16q/unrelated",
            unrelated_domain_id,
            CONFLICT_SLOT,
            unrelated_policy_root,
            configuration_root,
            &members[2].2,
            60,
        )?;

        let registration_rpc = cluster.validators[0].validator().rpc_addr.clone();
        let mut all_manifests = manifests
            .iter()
            .map(|(_, _, _, manifest)| manifest.clone())
            .collect::<Vec<_>>();
        all_manifests.extend(
            saturation_manifests
                .iter()
                .map(|(_, _, _, manifest)| manifest.clone()),
        );
        all_manifests.extend([conflict_a.clone(), conflict_b.clone(), unrelated.clone()]);
        for (nonce, manifest) in all_manifests.iter().enumerate() {
            let registration = signed_system_transaction(
                &cluster.validators[0].validator().keypair,
                SystemPayload::CallService {
                    service_id: AFT_EFFECT_REGISTRY_SERVICE_ID.into(),
                    method: REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD.into(),
                    params: serde_jcs::to_vec(manifest)?,
                },
                nonce as u64,
                CHAIN_ID.into(),
            )?;
            rpc::submit_transaction(&registration_rpc, &registration).await?;
        }
        let admitted_height = rpc::get_status(&registration_rpc).await?.height;
        for guard in &cluster.validators {
            wait_for_height(
                &guard.validator().rpc_addr,
                admitted_height,
                Duration::from_secs(60),
            )
            .await?;
        }

        let mut solo_elapsed_ms = Vec::new();
        for (member_position, (correct_process, domain, policy_root, manifest)) in
            manifests.iter().enumerate()
        {
            for process_index in 0..cluster.validators.len() {
                if process_index != *correct_process {
                    cluster.validators[process_index]
                        .validator_mut()
                        .kill_orchestration()
                        .await?;
                }
            }
            let correct_rpc = cluster.validators[*correct_process]
                .validator()
                .rpc_addr
                .clone();
            let candidate = m16q_candidate(
                manifest,
                network_id,
                configuration_root,
                *policy_root,
                *domain,
                members[member_position].0,
                &members[member_position].2,
            )?;
            let started = Instant::now();
            let response = tokio::time::timeout(
                Duration::from_secs(30),
                rpc::execute_aft_quv_effect(&correct_rpc, &manifest.effect_id, &candidate),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "M16Q sole-correct placement {member_position} exceeded its client timeout"
                )
            })??;
            let elapsed = started.elapsed().as_millis();
            let max_valid_reply_elapsed_ms =
                require_executed_nonportable_quv_receipt(&response)?;
            if max_valid_reply_elapsed_ms > 4_000 {
                return Err(anyhow::anyhow!(
                    "M16Q sole-correct placement {member_position} exceeded its qualified 4000ms reply envelope: {max_valid_reply_elapsed_ms}ms"
                ));
            }
            solo_elapsed_ms.push(elapsed);
            println!(
                "[M16Q-QUV] case=sole_correct member_position={member_position} process_index={correct_process} elapsed_ms={elapsed} max_valid_reply_elapsed_ms={max_valid_reply_elapsed_ms} qualified_envelope_ms=4000 result=executed"
            );

            for process_index in 0..cluster.validators.len() {
                if process_index != *correct_process {
                    cluster.validators[process_index]
                        .validator_mut()
                        .restart_orchestration_process()
                        .await?;
                }
            }
            let recovery_floor = rpc::get_status(&correct_rpc).await?.height.saturating_add(1);
            wait_for_height(&correct_rpc, recovery_floor, Duration::from_secs(120)).await?;
        }

        // Saturate every member's authenticated one-request-per-account lane:
        // four executors concurrently push independent valid operations to all
        // four members. Each member must serialize four durable ML-DSA replies
        // without allowing the other three accounts to consume the fourth
        // account's reserved admission slot or the qualified timing envelope.
        let saturation_started = Instant::now();
        let mut saturation_tasks = tokio::task::JoinSet::new();
        for (member_position, (process_index, domain, policy_root, manifest)) in
            saturation_manifests.iter().enumerate()
        {
            let candidate = m16q_candidate(
                manifest,
                network_id,
                configuration_root,
                *policy_root,
                *domain,
                members[member_position].0,
                &members[member_position].2,
            )?;
            let rpc_addr = cluster.validators[*process_index]
                .validator()
                .rpc_addr
                .clone();
            let effect_id = manifest.effect_id.clone();
            saturation_tasks.spawn(async move {
                rpc::execute_aft_quv_effect(&rpc_addr, &effect_id, &candidate).await
            });
        }
        let mut saturation_reply_elapsed_ms = Vec::new();
        while let Some(joined) = saturation_tasks.join_next().await {
            let response = joined.map_err(anyhow::Error::new)??;
            let reply_elapsed = require_executed_nonportable_quv_receipt(&response)?;
            if reply_elapsed > 4_000 {
                return Err(anyhow::anyhow!(
                    "M16Q authenticated saturation exceeded its qualified 4000ms reply envelope: {reply_elapsed}ms"
                ));
            }
            saturation_reply_elapsed_ms.push(reply_elapsed);
        }
        if saturation_reply_elapsed_ms.len() != members.len() {
            return Err(anyhow::anyhow!(
                "M16Q authenticated saturation did not complete every executor operation"
            ));
        }
        let saturation_elapsed_ms = saturation_started.elapsed().as_millis();
        println!(
            "[M16Q-QUV] case=authenticated_saturation operations={} elapsed_ms={saturation_elapsed_ms} max_valid_reply_elapsed_ms={:?} qualified_envelope_ms=4000 result=executed",
            saturation_reply_elapsed_ms.len(),
            saturation_reply_elapsed_ms.iter().max()
        );

        let conflict_candidate_a = m16q_candidate(
            &conflict_a,
            network_id,
            configuration_root,
            conflict_policy_root,
            conflict_domain,
            members[0].0,
            &members[0].2,
        )?;
        let conflict_candidate_b = m16q_candidate(
            &conflict_b,
            network_id,
            configuration_root,
            conflict_policy_root,
            conflict_domain,
            members[1].0,
            &members[1].2,
        )?;
        let conflict_rpc_a = cluster.validators[members[0].1]
            .validator()
            .rpc_addr
            .clone();
        let conflict_rpc_b = cluster.validators[members[1].1]
            .validator()
            .rpc_addr
            .clone();
        let conflict_started = Instant::now();
        let (result_a, result_b) = tokio::join!(
            rpc::execute_aft_quv_effect(
                &conflict_rpc_a,
                &conflict_a.effect_id,
                &conflict_candidate_a,
            ),
            rpc::execute_aft_quv_effect(
                &conflict_rpc_b,
                &conflict_b.effect_id,
                &conflict_candidate_b,
            )
        );
        let conflict_elapsed_ms = conflict_started.elapsed().as_millis();
        let mut conflict_accepts = 0_u8;
        for response in [result_a.as_ref().ok(), result_b.as_ref().ok()]
            .into_iter()
            .flatten()
        {
            require_executed_nonportable_quv_receipt(response)?;
            conflict_accepts += 1;
        }
        if conflict_accepts > 1 {
            return Err(anyhow::anyhow!(
                "two conflicting online QUV effects executed for one domain and slot"
            ));
        }
        println!(
            "[M16Q-QUV] case=concurrent_valid_conflict accepts={conflict_accepts} elapsed_ms={conflict_elapsed_ms} result=safe"
        );

        let unrelated_candidate = m16q_candidate(
            &unrelated,
            network_id,
            configuration_root,
            unrelated_policy_root,
            unrelated_domain,
            members[2].0,
            &members[2].2,
        )?;
        let unrelated_rpc = cluster.validators[members[2].1]
            .validator()
            .rpc_addr
            .clone();
        let unrelated_started = Instant::now();
        let unrelated_response = rpc::execute_aft_quv_effect(
            &unrelated_rpc,
            &unrelated.effect_id,
            &unrelated_candidate,
        )
        .await?;
        let unrelated_elapsed_ms = unrelated_started.elapsed().as_millis();
        require_executed_nonportable_quv_receipt(&unrelated_response)?;
        println!(
            "[M16Q-QUV] case=unrelated_after_conflict elapsed_ms={unrelated_elapsed_ms} result=executed"
        );
        println!(
            "[M16Q-SUMMARY] sole_correct_elapsed_ms={solo_elapsed_ms:?} conflict_elapsed_ms={conflict_elapsed_ms} conflict_accepts={conflict_accepts} unrelated_elapsed_ms={unrelated_elapsed_ms} delta_rt_ms={DELTA_RT_MILLIS}"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let shutdown = cluster.shutdown().await;
    run?;
    shutdown?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_pq_four_validator_timeout_quorum_and_restart() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let stable = tempfile::tempdir()?;
    let stable_path = stable.path().join("pq-aft-cluster");

    // Normal proposal cadence is safely below the pacemaker timeout. The test
    // forces a genuine timeout by stopping the validator scheduled to lead the
    // next height; the other three validators must then form the exact q=3
    // scoped ML-DSA certificate and continue in the next view. Full-mesh
    // bootstrapping exercises every pairwise ML-KEM/ML-DSA channel.
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "0"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "1000"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    let build_cluster = || {
        TestCluster::builder()
            .with_validators(4)
            .with_consensus_type("Aft")
            .with_aft_safety_mode(AftSafetyMode::ClassicBft)
            .with_pq_consensus_profile()
            .with_state_tree("IAVL")
            .with_chain_id(0xA17)
            .with_state_dir(stable_path.clone())
            .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 0xA17,
                grace_period_blocks: 0,
                accept_staged_during_grace: false,
                allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
                allow_downgrade: false,
            }))
    };

    let mut cluster = build_cluster().build().await?;
    let terminal_finality_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for (index, guard) in cluster.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_finality_errors = terminal_finality_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_finality_errors
                        .lock()
                        .expect("terminal-finality evidence lock poisoned")
                        .push(format!("node {index}: {line}"));
                }
                if ["pq", "timeout", "fallback", "quorum", "error", "failed"]
                    .iter()
                    .any(|needle| normalized.contains(needle))
                {
                    println!("[PQ-AFT node {index}] {line}");
                }
            }
        });
    }
    let first_run = async {
        let mut observed_heights = Vec::with_capacity(cluster.validators.len());
        for guard in &cluster.validators {
            observed_heights.push(rpc::get_status(&guard.validator().rpc_addr).await?.height);
        }
        let baseline = observed_heights.into_iter().max().unwrap_or(1);

        // Fail a leader three heights ahead. The two immediately preceding
        // heights have different round-robin leaders, allowing the three
        // survivors to converge after the process stop before they encounter
        // the missing proposer.
        let timeout_height = baseline + 3;
        let mut validator_order = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(index, guard)| {
                let keypair = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("strict PQ cluster must retain its ML-DSA validator key");
                let account = account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &keypair.public_key().to_bytes(),
                )
                .expect("ML-DSA validator account derivation must succeed");
                (account, index)
            })
            .collect::<Vec<_>>();
        validator_order.sort_by_key(|(account, _)| *account);
        let failed_leader_index = validator_order[((timeout_height - 1) as usize) % 4].1;
        let observer_index = if failed_leader_index == 0 { 1 } else { 0 };
        let first_rpc = cluster.validators[observer_index]
            .validator()
            .rpc_addr
            .clone();

        println!(
            "--- PQ AFT fault drill: baseline={baseline}, timeout_height={timeout_height}, failed_leader_index={failed_leader_index}, observer_index={observer_index} ---"
        );

        {
            let backend = cluster.validators[failed_leader_index]
                .validator_mut()
                .backend
                .as_any_mut()
                .downcast_mut::<ProcessBackend>()
                .ok_or_else(|| {
                    anyhow::anyhow!("PQ timeout drill requires the process test backend")
                })?;
            let mut leader = backend
                .orchestration_process
                .take()
                .ok_or_else(|| anyhow::anyhow!("scheduled leader process was not running"))?;
            leader.start_kill()?;
            let _ = leader.wait().await?;
        }

        // A cold debug build verifies three independent ML-DSA timeout votes
        // and a full ML-DSA proposal/QC while repeatedly exercising dead-peer
        // transport. The protocol timeout remains 30 seconds; this outer
        // harness deadline only gives the exact-q recovery enough host budget
        // to finish before teardown on contended CI workers.
        wait_for_height(&first_rpc, timeout_height + 1, Duration::from_secs(240)).await?;

        let mut saw_timeout_certificate = false;
        let mut saw_exact_q_parent = false;
        for height in 1..=timeout_height + 1 {
            let block = rpc::get_block_by_height_resilient(&first_rpc, height)
                .await?
                .ok_or_else(|| anyhow::anyhow!("PQ AFT cluster omitted block {height}"))?;
            if block.header.producer_key_suite != SignatureSuite::ML_DSA_44 {
                return Err(anyhow::anyhow!(
                    "block {height} downgraded producer suite to {:?}",
                    block.header.producer_key_suite
                ));
            }
            if block.header.timeout_certificate.is_some() {
                return Err(anyhow::anyhow!(
                    "block {height} carried legacy unscoped timeout evidence"
                ));
            }
            if let Some(certificate) = block.header.aft_timeout_certificate.as_ref() {
                if certificate.votes.len() != 3 {
                    return Err(anyhow::anyhow!(
                        "block {height} carried {} scoped timeout votes; expected exact q=3",
                        certificate.votes.len()
                    ));
                }
                if certificate.height != timeout_height {
                    return Err(anyhow::anyhow!(
                        "block {height} carried timeout evidence for unexpected height {}",
                        certificate.height
                    ));
                }
                saw_timeout_certificate = true;
            }
            if height > 1 && block.header.parent_qc.signatures.len() == 3 {
                saw_exact_q_parent = true;
            }
        }
        if !saw_timeout_certificate {
            return Err(anyhow::anyhow!(
                "four-validator PQ AFT drill formed no scoped timeout certificate"
            ));
        }
        if !saw_exact_q_parent {
            return Err(anyhow::anyhow!(
                "four-validator PQ AFT drill formed no exact q=3 parent quorum"
            ));
        }
        Ok(rpc::get_status(&first_rpc).await?.height)
    }
    .await;
    let first_shutdown = cluster.shutdown().await;
    let before_restart = first_run?;
    first_shutdown?;

    let resumed = build_cluster().build().await?;
    for (index, guard) in resumed.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_finality_errors = terminal_finality_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_finality_errors
                        .lock()
                        .expect("terminal-finality evidence lock poisoned")
                        .push(format!("restarted node {index}: {line}"));
                }
            }
        });
    }
    let resumed_rpc = resumed.validators[0].validator().rpc_addr.clone();
    let resumed_run = async {
        wait_for_height(&resumed_rpc, before_restart + 2, Duration::from_secs(240)).await?;
        let resumed_block = rpc::get_block_by_height_resilient(&resumed_rpc, before_restart + 1)
            .await?
            .ok_or_else(|| anyhow::anyhow!("PQ AFT cluster did not continue after restart"))?;
        if resumed_block.header.producer_key_suite != SignatureSuite::ML_DSA_44 {
            return Err(anyhow::anyhow!(
                "resumed PQ AFT cluster downgraded its producer suite"
            ));
        }
        Ok(())
    }
    .await;
    let resumed_shutdown = resumed.shutdown().await;
    resumed_run?;
    resumed_shutdown?;
    let terminal_finality_errors = terminal_finality_errors
        .lock()
        .expect("terminal-finality evidence lock poisoned")
        .clone();
    if !terminal_finality_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "PQ AFT drill emitted terminal runtime-finality failures:\n{}",
            terminal_finality_errors.join("\n")
        ));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_pq_hash_fallback_executes_virtual_block() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let stable = tempfile::tempdir()?;
    let stable_path = stable.path().join("pq-hash-fallback");
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        // Startup readiness may observe one node producing the next block
        // while it samples the others. Exact fallback convergence is checked
        // explicitly below, so requiring a zero-height observation window
        // only makes the cold-restart half race normal forward progress.
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "500"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_ARMED", "1"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_HEIGHT", "4"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_VIEWS", "3"),
        ("IOI_TEST_AFT_STAGE_OPTIMISTIC_PROJECTION", "1"),
    ]);
    let build_cluster = || {
        TestCluster::builder()
            .with_validators(4)
            .with_consensus_type("Aft")
            .with_aft_safety_mode(AftSafetyMode::ClassicBft)
            .with_pq_consensus_profile()
            .with_state_tree("IAVL")
            .with_chain_id(0xA18)
            .with_state_dir(stable_path.clone())
            .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 0xA18,
                grace_period_blocks: 0,
                accept_staged_during_grace: false,
                allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
                allow_downgrade: false,
            }))
    };
    let cluster = build_cluster().build().await?;

    let terminal_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for (index, guard) in cluster.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_errors = terminal_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_errors
                        .lock()
                        .expect("fallback error lock poisoned")
                        .push(format!("node {index}: {line}"));
                }
                if normalized.contains("hash")
                    || normalized.contains("fallback")
                    || normalized.contains("timeout")
                {
                    if normalized.contains("\"level\":\"debug\"") {
                        continue;
                    } else if normalized.contains("stack backtrace") {
                        println!("[PQ-HASH-FALLBACK node {index}] timeout path returned an error (backtrace elided)");
                    } else {
                        println!("[PQ-HASH-FALLBACK node {index}] {line}");
                    }
                }
            }
        });
    }

    let observer = cluster.validators[0].validator().rpc_addr.clone();
    let run = async {
        wait_for_height(&observer, 3, Duration::from_secs(60)).await?;
        let optimistic_projection = tokio::time::timeout(Duration::from_secs(60), async {
            'wait_for_projection: loop {
                for guard in &cluster.validators {
                    if let Some(block) =
                        rpc::get_block_by_height_resilient(&guard.validator().rpc_addr, 4).await?
                    {
                        if block.header.view == 0 && block.header.signature.is_empty() {
                            break 'wait_for_projection Ok::<_, anyhow::Error>(block);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("normal producer staged no optimistic height-4 projection"))??;
        let optimistic_projection_hash = optimistic_projection.header.hash()?;
        println!(
            "--- observed production-generated speculative workload projection at height 4: {} ---",
            hex::encode(&optimistic_projection_hash)
        );
        // Hash-only agreement plus four independent ML-DSA-heavy offline
        // admission checks is deliberately the pessimistic path. Debug CI on
        // constrained hosts can spend well beyond eight minutes on the
        // complete fallback plus native-child verification, so this
        // wall-clock guard must not masquerade as a protocol timeout. The
        // first optimistic child may use the
        // virtual block's empty-signature canonical reference only while the
        // engine retains the separately typed, fully verified asynchronous
        // predecessor proof. It must never manufacture a native QC.
        wait_for_height(&observer, 5, Duration::from_secs(900)).await?;
        let block = rpc::get_block_by_height_resilient(&observer, 4)
            .await?
            .ok_or_else(|| anyhow::anyhow!("hash fallback omitted virtual block 4"))?;
        if block.header.view != 4
            || !block.header.signature.is_empty()
            || block.header.producer_key_suite != SignatureSuite::ML_DSA_44
            || block.header.aft_timeout_certificate.is_some()
        {
            return Err(anyhow::anyhow!(
                "height 4 is not the canonical hash-fallback virtual envelope: view={}, signature_len={}, suite={:?}, timeout_extension={}",
                block.header.view,
                block.header.signature.len(),
                block.header.producer_key_suite,
                block.header.aft_timeout_certificate.is_some(),
            ));
        }
        if block.header.parent_qc.height != 3 {
            return Err(anyhow::anyhow!(
                "hash fallback virtual block did not bind the exact height-3 high QC"
            ));
        }
        let expected_hash = block.header.hash()?;
        if expected_hash == optimistic_projection_hash {
            return Err(anyhow::anyhow!(
                "hash fallback did not replace the staged optimistic workload projection"
            ));
        }
        for guard in &cluster.validators {
            wait_for_height(
                &guard.validator().rpc_addr,
                5,
                Duration::from_secs(120),
            )
            .await?;
            let peer_block = rpc::get_block_by_height_resilient(&guard.validator().rpc_addr, 4)
                .await?
                .ok_or_else(|| anyhow::anyhow!("peer omitted hash fallback block 4"))?;
            if peer_block.header.hash()? != expected_hash {
                return Err(anyhow::anyhow!(
                    "validators executed different hash-fallback virtual blocks"
                ));
            }
        }
        // Height RPCs expose the workload's live candidate as well as the
        // admitted floor. Wait until every validator has crossed H=5 before
        // asserting the stabilized re-entry header; an earlier same-height
        // candidate may still be inside the bounded replacement window.
        let optimistic_child = rpc::get_block_by_height_resilient(&observer, 5)
            .await?
            .ok_or_else(|| anyhow::anyhow!("optimistic path did not resume at height 5"))?;
        if optimistic_child.header.parent_hash != expected_hash.as_slice()
            || optimistic_child.header.parent_qc.height != 4
            || optimistic_child.header.parent_qc.block_hash != expected_hash.as_slice()
            || !optimistic_child.header.parent_qc.signatures.is_empty()
            || !optimistic_child
                .header
                .parent_qc
                .aggregated_signature
                .is_empty()
            || !optimistic_child.header.parent_qc.signers_bitfield.is_empty()
            || optimistic_child.header.signature.is_empty()
            || optimistic_child.header.producer_key_suite != SignatureSuite::ML_DSA_44
        {
            return Err(anyhow::anyhow!(
                "height 5 did not use the typed async-parent bridge followed by native PQ production: parent_hash_match={}, parent_qc_height={}, parent_qc_hash_match={}, parent_qc_signatures={}, parent_qc_aggregate={}, parent_qc_bitfield={}, child_signature={}, child_suite={:?}",
                optimistic_child.header.parent_hash == expected_hash.as_slice(),
                optimistic_child.header.parent_qc.height,
                optimistic_child.header.parent_qc.block_hash == expected_hash.as_slice(),
                optimistic_child.header.parent_qc.signatures.len(),
                optimistic_child.header.parent_qc.aggregated_signature.len(),
                optimistic_child.header.parent_qc.signers_bitfield.len(),
                optimistic_child.header.signature.len(),
                optimistic_child.header.producer_key_suite,
            ));
        }
        let metrics = aft_hash_async_metrics(
            &cluster.validators[0]
                .validator()
                .orchestration_telemetry_addr,
        )
        .await?;
        for stage in [
            "execution_prepare",
            "workload_execution",
            "runtime_stage",
            "runtime_admission",
            "parent_proof_install",
        ] {
            let needle = format!(
                "ioi_aft_hash_async_stage_duration_seconds_count{{stage=\"{stage}\"}} "
            );
            if !metrics.lines().any(|line| line.starts_with(&needle)) {
                return Err(anyhow::anyhow!(
                    "production fallback metrics omitted stage {stage}"
                ));
            }
        }
        println!("--- AFT hash-async production metrics ---");
        for line in metrics.lines().filter(|line| {
            line.starts_with("ioi_aft_hash_async_messages_total")
                || line.starts_with("ioi_aft_hash_async_bytes_total")
                || line.starts_with("ioi_aft_hash_async_stage_duration_seconds_count")
                || line.starts_with("ioi_aft_hash_async_stage_duration_seconds_sum")
        }) {
            println!("{line}");
        }
        Ok::<_, anyhow::Error>(expected_hash)
    }
    .await;
    let shutdown = cluster.shutdown().await;
    let expected_hash = run?;
    shutdown?;

    // Reopen the exact stable process state. Startup must replay the durable
    // fallback transition, reconstruct the compact terminal session, reinstall
    // the typed async-parent proof, and continue without reopening agreement or
    // manufacturing a native QC for the virtual block.
    let resumed = build_cluster().build().await?;
    let resumed_log_tails =
        std::sync::Arc::new(std::sync::Mutex::new(vec![
            Vec::<String>::new();
            resumed.validators.len()
        ]));
    for (index, guard) in resumed.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_errors = terminal_errors.clone();
        let resumed_log_tails = resumed_log_tails.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                {
                    const MAX_DIAGNOSTIC_LINES: usize = 256;
                    let mut tails = resumed_log_tails
                        .lock()
                        .expect("restart diagnostic log lock poisoned");
                    let tail = &mut tails[index];
                    tail.push(line.clone());
                    if tail.len() > MAX_DIAGNOSTIC_LINES {
                        tail.remove(0);
                    }
                }
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_errors
                        .lock()
                        .expect("fallback error lock poisoned")
                        .push(format!("restarted node {index}: {line}"));
                }
            }
        });
    }
    let resumed_rpc = resumed.validators[0].validator().rpc_addr.clone();
    let resumed_run = async {
        if let Err(wait_error) = wait_for_height(&resumed_rpc, 7, Duration::from_secs(240)).await {
            let mut diagnostics = vec![format!("observer wait failed: {wait_error:#}")];
            for (index, guard) in resumed.validators.iter().enumerate() {
                let rpc_addr = &guard.validator().rpc_addr;
                let height = rpc::get_chain_height(rpc_addr)
                    .await
                    .map(|height| height.to_string())
                    .unwrap_or_else(|error| format!("rpc-error({error:#})"));
                let mut available = Vec::new();
                for height_to_probe in 4..=7 {
                    match rpc::get_block_by_height_resilient(rpc_addr, height_to_probe).await {
                        Ok(Some(block)) => available.push(format!(
                            "H{}:view{}:sig{}",
                            height_to_probe,
                            block.header.view,
                            block.header.signature.len()
                        )),
                        Ok(None) => available.push(format!("H{height_to_probe}:missing")),
                        Err(error) => {
                            available.push(format!("H{height_to_probe}:rpc-error({error:#})"))
                        }
                    }
                }
                diagnostics.push(format!(
                    "node {index}: reported_height={height}; {}",
                    available.join(", ")
                ));
            }
            let tails = resumed_log_tails
                .lock()
                .expect("restart diagnostic log lock poisoned")
                .clone();
            for (index, tail) in tails.iter().enumerate() {
                diagnostics.push(format!(
                    "node {index} orchestration tail ({} lines):\n{}",
                    tail.len(),
                    tail.join("\n")
                ));
            }
            return Err(anyhow::anyhow!(
                "post-restart PQ AFT progress diagnostics:\n{}",
                diagnostics.join("\n")
            ));
        }
        let recovered_virtual = rpc::get_block_by_height_resilient(&resumed_rpc, 4)
            .await?
            .ok_or_else(|| anyhow::anyhow!("restart omitted hash-fallback block 4"))?;
        if recovered_virtual.header.hash()? != expected_hash {
            return Err(anyhow::anyhow!(
                "restart changed the admitted hash-fallback block"
            ));
        }
        let resumed_child = rpc::get_block_by_height_resilient(&resumed_rpc, 6)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("hash-fallback cluster did not advance after restart")
            })?;
        if resumed_child.header.signature.is_empty()
            || resumed_child.header.producer_key_suite != SignatureSuite::ML_DSA_44
        {
            return Err(anyhow::anyhow!(
                "post-restart optimistic production downgraded or lost authentication"
            ));
        }
        Ok(())
    }
    .await;
    let resumed_shutdown = resumed.shutdown().await;
    resumed_run?;
    resumed_shutdown?;
    let terminal_errors = terminal_errors
        .lock()
        .expect("fallback error lock poisoned")
        .clone();
    if !terminal_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "PQ hash-fallback drill emitted terminal failures:\n{}",
            terminal_errors.join("\n")
        ));
    }
    Ok(())
}
