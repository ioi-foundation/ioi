// Process qualification of consecutive Fixed-domain slots and local reopen.
// This finite workload does not derive the aggregate preparation bound.

async fn next_readiness_event(
    events: &mut tokio::sync::mpsc::Receiver<Result<serde_json::Value, String>>,
    event: &str,
    slot: u64,
) -> Result<serde_json::Value> {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let fields = events
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("readiness diagnostic drain ended"))?
                .map_err(anyhow::Error::msg)?;
            if fields["event"] == event && fields["slot"].as_u64() == Some(slot) {
                return Ok(fields);
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("missing readiness event {event} for slot {slot}"))?
}

async fn next_readiness_or_call_end<T>(
    events: &mut tokio::sync::mpsc::Receiver<Result<serde_json::Value, String>>,
    call: &mut tokio::task::JoinHandle<Result<T>>,
    slot: u64,
) -> Result<serde_json::Value> {
    tokio::select! {
        biased;
        event = next_readiness_event(events, "foreground_readiness_wait", slot) => event,
        result = call => match result {
            Ok(Err(error)) => Err(error.context(format!("slot {slot} RPC ended before readiness wait"))),
            Err(error) => Err(anyhow::Error::new(error).context(format!("slot {slot} RPC task ended before readiness wait"))),
            Ok(Ok(_)) => Err(anyhow::anyhow!("slot {slot} RPC succeeded without its required readiness wait observation")),
        },
    }
}

fn checked_readiness_observation(fields: &serde_json::Value, nonce: &str) -> Result<()> {
    let number = |key: &str| -> Result<u128> {
        let value = fields[key]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing decimal {key}"))?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(anyhow::anyhow!("invalid decimal {key}"));
        }
        Ok(value.parse()?)
    };
    let required = number("required_remaining_nanos")?;
    let elapsed = number("elapsed_nanos")?;
    if fields["nonce"] != nonce
        || fields["deadline_elapsed"] != true
        || required < Duration::from_secs(15).as_nanos()
        || elapsed < required
    {
        return Err(anyhow::anyhow!(
            "readiness wait was absent, short, early or mismatched: {fields}"
        ));
    }
    Ok(())
}

fn readiness_live_nonce(
    response: &ioi_ipc::public::ExecuteAftQuvEffectResponse,
    candidate: &QuvCandidateV0,
) -> Result<String> {
    let receipt: ConsequenceReceiptV1 = serde_json::from_slice(&response.consequence_receipt_jcs)?;
    let audit = receipt
        .online_authorization_audit
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing live audit"))?;
    let evidence: QuvAcceptedAuditEvidenceV0 =
        codec::from_bytes_canonical(&audit.protocol_evidence).map_err(anyhow::Error::msg)?;
    if &evidence.request.candidate != candidate {
        return Err(anyhow::anyhow!("live audit changed the supplied candidate"));
    }
    if let Some(directory) = std::env::var_os("IOI_AFT_BENCH_TRACE_DIR") {
        std::fs::write(
            std::path::Path::new(&directory)
                .join(format!("{}.receipt.json", receipt.manifest.effect_id)),
            &response.consequence_receipt_jcs,
        )?;
    }
    Ok(hex::encode(evidence.request.verifier_nonce))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_quv_consecutive_slots_wait_and_reopen_without_blocking_unrelated_effects(
) -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    const CHAIN_ID: u32 = 0xA21;
    const DELTA: u64 = 5_000;
    const CONTINUATION: u64 = 5_000;
    const READINESS: u64 = 40_000;
    let domain_name = "domain://aft-e2e/readiness/sequence";
    let probe_name = "domain://aft-e2e/readiness/unrelated";
    let domain = conflict_domain_id_commitment(domain_name).map_err(anyhow::Error::msg)?;
    let probe_domain = conflict_domain_id_commitment(probe_name).map_err(anyhow::Error::msg)?;
    let make_policy = |domain_id| AftQuvDomainPolicyV0 {
        domain_id,
        authority_mode: QuvAuthorityModeV0::Unowned,
        owner: None,
        bootstrap: ioi_types::app::QuvDomainBootstrapV0::Fixed {
            initial_slot: 1,
            predecessor: [77; 32],
        },
        preparation: ioi_types::app::QuvPreparationPolicyV0::Independent {
            max_attempts_per_slot: 2,
            service_millis: DELTA + CONTINUATION,
            readiness_millis: READINESS,
        },
        delta_rt_millis: DELTA,
        continuation_millis: CONTINUATION,
        operation_service_millis: DELTA + CONTINUATION,
        qualified_delta_rt_envelope_millis: 4_000,
        qualified_max_configured_members: 4,
    };
    let policy = make_policy(domain);
    let probe_policy = make_policy(probe_domain);
    let policy_root = |p: &AftQuvDomainPolicyV0| {
        quv_policy_root(
            p.domain_id,
            p.authority_mode,
            p.owner,
            p.delta_rt_millis,
            p.continuation_millis,
            &p.bootstrap,
            &p.preparation,
            p.operation_service_millis,
        )
    };
    let root = policy_root(&policy)?;
    let probe_root = policy_root(&probe_policy)?;
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_BUILD_PROFILE", "release"),
        ("IOI_TEST_ORCH_RUST_LOG", "info,quv=debug,network=debug"),
        ("IOI_TEST_VALIDATOR_LAUNCH_CONCURRENCY", "2"),
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS", "180"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "500"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);
    let mut cluster = TestCluster::builder()
        .with_validators(4)
        .with_consensus_type("Aft")
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_pq_consensus_profile()
        .with_state_tree("IAVL")
        .with_chain_id(CHAIN_ID)
        .with_quv_domain_policy(policy)
        .with_quv_domain_policy(probe_policy)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: CHAIN_ID,
            grace_period_blocks: 0,
            accept_staged_during_grace: false,
            allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
            allow_downgrade: false,
        }))
        .build()
        .await?;
    let run = async {
        let mut members = cluster.validators.iter().enumerate().map(|(index, guard)| {
            let key = guard.validator().pqc_keypair.as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing ML-DSA fixture key"))?.clone();
            let account = AccountId(account_id_from_key_material(SignatureSuite::ML_DSA_44,
                &key.public_key().to_bytes())?);
            Ok((account, index, key))
        }).collect::<Result<Vec<_>>>()?;
        members.sort_by_key(|entry| entry.0);
        let expected = members.iter().map(|entry| entry.0).collect::<HashSet<_>>();
        let active_set = ValidatorSetV1 {
            effective_from_height: 1, total_weight: 4,
            validators: members.iter().map(|entry| ValidatorV1 {
                account_id: entry.0, weight: 1,
                consensus_key: ActiveKeyRecord { suite: SignatureSuite::ML_DSA_44,
                    public_key_hash: entry.0.0, since_height: 0 },
            }).collect(),
        };
        let configuration = ioi_types::app::canonical_validator_set_hash(&active_set).map_err(anyhow::Error::msg)?;
        let network = ioi_crypto::algorithms::hash::sha256(cluster.genesis_content.as_bytes())?;
        let (account, executor, endpoint) = &members[0];
        let executor = *executor;
        let rpc_addr = cluster.validators[executor].validator().rpc_addr.clone();
        let mut manifests = Vec::new();
        let mut candidates = Vec::new();
        let mut predecessor = [77; 32];
        for slot in 1..=3 {
            let mut manifest = m16q_effect_manifest(&format!("readiness-slot-{slot}"),
                "resource://aft-e2e/readiness", domain_name, slot, root, configuration,
                endpoint, 70 + slot as u8)?;
            manifest.online_authorization_predecessor = Some(predecessor);
            manifest.idempotency_key = manifest.query_unanimity_idempotency_key()?;
            manifest.validate()?;
            let candidate = m16q_candidate(&manifest, network, configuration, root, domain, *account, endpoint)?;
            predecessor = ioi_consensus::aft::query_unanimity::quv_candidate_hash(&candidate)?;
            manifests.push(manifest); candidates.push(candidate);
        }
        let probe = m16q_effect_manifest("readiness-unrelated", "resource://aft-e2e/readiness-unrelated",
            probe_name, 1, probe_root, configuration, endpoint, 80)?;
        let probe_candidate = m16q_candidate(&probe, network, configuration, probe_root, probe_domain, *account, endpoint)?;
        let member_hex = members.iter().map(|entry| hex::encode(entry.0.as_ref())).collect::<Vec<_>>().join(",");
        let candidate_hex = candidates.iter().map(|candidate| ioi_consensus::aft::query_unanimity::quv_candidate_hash(candidate).map(hex::encode)).collect::<std::result::Result<Vec<_>, _>>()?.join(",");
        println!("[M16Q-READINESS-EXPECT] configuration={} domain={} probe_domain={} executor={} members={} candidates={} probe_candidate={} decision_millis={DELTA} readiness_millis={READINESS} reply_envelope_millis=4000",
            hex::encode(configuration), hex::encode(domain), hex::encode(probe_domain), hex::encode(account.as_ref()), member_hex, candidate_hex,
            hex::encode(ioi_consensus::aft::query_unanimity::quv_candidate_hash(&probe_candidate)?));
        for (nonce, manifest) in manifests.iter().chain(std::iter::once(&probe)).enumerate() {
            let tx = signed_system_transaction(&cluster.validators[0].validator().keypair,
                SystemPayload::CallService { service_id: AFT_EFFECT_REGISTRY_SERVICE_ID.into(),
                    method: REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD.into(), params: serde_jcs::to_vec(manifest)? },
                nonce as u64, CHAIN_ID.into())?;
            rpc::submit_transaction(&cluster.validators[0].validator().rpc_addr, &tx).await?;
        }
        // Continuously drain diagnostics so a long wait cannot conceal lost events.
        let (mut logs, _, _) = cluster.validators[executor].validator().subscribe_logs();
        let (send, mut events) = tokio::sync::mpsc::channel(16);
        let domain_hex = hex::encode(domain);
        let drain = tokio::spawn(async move {
            loop {
                match logs.recv().await {
                    Ok(line) => {
                        let Ok(record) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                        let fields = &record["fields"];
                        if record["target"] == "quv" && fields["domain"] == domain_hex
                            && matches!(fields["event"].as_str(), Some("foreground_readiness_wait" | "foreground_readiness_admitted"))
                            && send.send(Ok(fields.clone())).await.is_err() { return; }
                    }
                    Err(error) => { let _ = send.send(Err(error.to_string())).await; return; }
                }
            }
        });
        let cases = async {
            let first = tokio::time::timeout(Duration::from_secs(30),
                rpc::execute_aft_quv_effect(&rpc_addr, &manifests[0].effect_id, &candidates[0])).await??;
            let max_reply = require_executed_nonportable_quv_receipt(&first, &expected, &expected)?;
            if max_reply > 4_000 { return Err(anyhow::anyhow!("parent exceeded reply envelope")); }
            let parent_nonce = readiness_live_nonce(&first, &candidates[0])?;
            println!("[M16Q-READINESS] slot=1 nonce={parent_nonce} result=executed max_valid_reply_elapsed_ms={max_reply}");
            for index in 1..3 {
                if index == 2 {
                    cluster.validators[executor].validator_mut().kill_orchestration().await?;
                    cluster.validators[executor].validator_mut().restart_orchestration_process().await?;
                }
                let call_rpc = rpc_addr.clone();
                let effect_id = manifests[index].effect_id.clone();
                let candidate = candidates[index].clone();
                let mut call = tokio::spawn(async move {
                    tokio::time::timeout(Duration::from_secs(90),
                        rpc::execute_aft_quv_effect(&call_rpc, &effect_id, &candidate)).await?
                });
                let slot = index as u64 + 1;
                let waiting = next_readiness_or_call_end(&mut events, &mut call, slot).await?;
                let nonce = waiting["nonce"].as_str().ok_or_else(|| anyhow::anyhow!("missing waiting nonce"))?.to_owned();
                if index == 1 {
                    let replay = tokio::time::timeout(Duration::from_secs(5),
                        rpc::execute_aft_quv_effect(&rpc_addr, &manifests[0].effect_id, &candidates[0])).await??;
                    if replay.portable_final_receipt || replay.consequence_receipt_jcs != first.consequence_receipt_jcs {
                        return Err(anyhow::anyhow!("parent replay changed while child waited"));
                    }
                    let unrelated = tokio::time::timeout(Duration::from_secs(20),
                        rpc::execute_aft_quv_effect(&rpc_addr, &probe.effect_id, &probe_candidate)).await??;
                    let probe_max = require_executed_nonportable_quv_receipt(&unrelated, &expected, &expected)?;
                    if probe_max > 4_000 || call.is_finished() {
                        return Err(anyhow::anyhow!("unrelated operation missed its envelope or did not finish during the child wait"));
                    }
                    let probe_nonce = readiness_live_nonce(&unrelated, &probe_candidate)?;
                    println!("[M16Q-READINESS] case=unrelated_during_wait nonce={probe_nonce} result=executed terminal_parent_replay=true");
                }
                let admitted = next_readiness_event(&mut events, "foreground_readiness_admitted", slot).await?;
                checked_readiness_observation(&admitted, &nonce)?;
                let response = call.await??;
                let max_reply = require_executed_nonportable_quv_receipt(&response, &expected, &expected)?;
                if max_reply > 4_000 { return Err(anyhow::anyhow!("child exceeded reply envelope")); }
                if readiness_live_nonce(&response, &candidates[index])? != nonce {
                    return Err(anyhow::anyhow!("child did not consume the matching fresh live operation"));
                }
                println!("[M16Q-READINESS] slot={slot} nonce={nonce} result=executed restarted={} max_valid_reply_elapsed_ms={max_reply} required_remaining_nanos={} elapsed_nanos={}",
                    index == 2, admitted["required_remaining_nanos"], admitted["elapsed_nanos"]);
            }
            Ok::<(), anyhow::Error>(())
        }.await;
        drain.abort();
        let _ = drain.await;
        cases
    }.await;
    let shutdown = cluster.shutdown().await;
    run?;
    shutdown?;
    Ok(())
}

#[test]
fn readiness_observation_requires_positive_wait_and_exact_nonce() {
    let nonce = "11".repeat(32);
    let good = serde_json::json!({
        "nonce": nonce, "deadline_elapsed": true,
        "required_remaining_nanos": "15000000000", "elapsed_nanos": "15000000000"
    });
    checked_readiness_observation(&good, &nonce).unwrap();
    for (key, value) in [
        ("nonce", serde_json::json!("22".repeat(32))),
        ("deadline_elapsed", serde_json::json!(false)),
        ("required_remaining_nanos", serde_json::json!("0")),
        ("elapsed_nanos", serde_json::json!("14999999999")),
        ("elapsed_nanos", serde_json::json!(15000000000_u64)),
        ("elapsed_nanos", serde_json::json!("1.5e10")),
        ("elapsed_nanos", serde_json::json!("-1")),
        ("elapsed_nanos", serde_json::json!("")),
        ("elapsed_nanos", serde_json::Value::Null),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(
            checked_readiness_observation(&bad, &nonce).is_err(),
            "accepted invalid {key}: {bad}"
        );
    }
}

#[tokio::test]
async fn readiness_wait_surfaces_early_rpc_error_without_diagnostic_timeout() {
    let (_sender, mut events) = tokio::sync::mpsc::channel(1);
    let mut call = tokio::spawn(async {
        Err::<(), anyhow::Error>(
            tonic::Status::failed_precondition("fixture admission unavailable").into(),
        )
    });
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        next_readiness_or_call_end(&mut events, &mut call, 3),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<tonic::Status>().unwrap().message(),
        "fixture admission unavailable"
    );
    assert!(format!("{error:#}").contains("slot 3 RPC ended before readiness wait"));
    let mut call = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });
    assert!(next_readiness_or_call_end(&mut events, &mut call, 3)
        .await
        .is_err());
}
