// Process qualification of R1 finding 007's FIRST-CONTACT trace: a Byzantine
// process B is launched from the start with the test-only status override, so
// the very first status response B ever sends (and every later one) claims the
// sole-correct member C's account. No peer holds a prior authenticated
// enrollment for B. A live operation on C's executor must still collect the
// configured replies through carriers bound only by proven ML-DSA keys, B must
// never be authenticated under C's account anywhere, and C's own carrier must
// authenticate normally on every other process.

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_quv_status_squat_first_contact_keeps_genuine_carriers() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    const CHAIN_ID: u32 = 0xA23;
    const DELTA: u64 = 5_000;
    const QUALIFIED_ENVELOPE_MS: u64 = 4_500;
    const CONTINUATION: u64 = 8_000;
    const CLAIMED_INDEX: usize = 0;
    const CLAIMANT_INDEX: usize = 1;
    let warmup_names = [
        "domain://aft-e2e/status-squat/warmup-1",
        "domain://aft-e2e/status-squat/warmup-2",
    ];
    let measured_name = "domain://aft-e2e/status-squat/measured";
    let warmup_domains = warmup_names
        .iter()
        .map(|name| conflict_domain_id_commitment(name).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<[u8; 32]>>>()?;
    let measured_domain = conflict_domain_id_commitment(measured_name).map_err(anyhow::Error::msg)?;
    // C's ML-DSA key is fixed before build so B's launch environment can name
    // C's account before any process exists.
    let fixture_pq_keys = {
        let scheme = ioi_crypto::sign::dilithium::MldsaScheme::new(
            ioi_crypto::security::SecurityLevel::Level2,
        );
        (0..4)
            .map(|_| scheme.generate_keypair().map_err(|error| anyhow::anyhow!(error.to_string())))
            .collect::<Result<Vec<_>>>()?
    };
    let claimed_account = AccountId(account_id_from_key_material(
        SignatureSuite::ML_DSA_44,
        &fixture_pq_keys[CLAIMED_INDEX].public_key().to_bytes(),
    )?);
    let claimant_account = AccountId(account_id_from_key_material(
        SignatureSuite::ML_DSA_44,
        &fixture_pq_keys[CLAIMANT_INDEX].public_key().to_bytes(),
    )?);
    let claimed_hex = hex::encode(claimed_account.as_ref());
    let standard_preparation = ioi_types::app::QuvPreparationPolicyV0::Independent {
        max_attempts_per_slot: 2,
        service_millis: DELTA + CONTINUATION,
        readiness_millis: 1_000_000,
    };
    let generous_quota = ioi_types::app::QuvPushAdmissionPolicyV0 {
        max_requests_per_identity: 64,
        window_millis: DELTA,
    };
    let make_policy = |domain_id| AftQuvDomainPolicyV0 {
        authority_slots: 256,
        domain_id,
        authority_mode: QuvAuthorityModeV0::Unowned,
        owner: None,
        bootstrap: ioi_types::app::QuvDomainBootstrapV0::Fixed {
            initial_slot: 1,
            predecessor: [77; 32],
        },
        preparation: standard_preparation,
        delta_rt_millis: DELTA,
        continuation_millis: CONTINUATION,
        operation_service_millis: DELTA + CONTINUATION,
        push_admission: generous_quota,
        qualified_delta_rt_envelope_millis: QUALIFIED_ENVELOPE_MS,
        qualified_max_configured_members: 4,
    };
    let policies = vec![
        make_policy(warmup_domains[0]),
        make_policy(warmup_domains[1]),
        make_policy(measured_domain),
    ];
    let roots = policies
        .iter()
        .map(|p| {
            quv_policy_root(
                p.domain_id,
                p.authority_mode,
                p.owner,
                p.delta_rt_millis,
                p.continuation_millis,
                &p.bootstrap,
                &p.preparation,
                p.operation_service_millis,
                p.authority_slots,
                p.push_admission,
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let warmup_roots = [roots[0], roots[1]];
    let measured_root = roots[2];
    // B never advertises its own account, so no peer can bind B's carrier
    // and B is outside strict-PQ consensus for the whole run: every view it
    // leads times out. A shorter view timeout than the sibling fixtures keeps
    // block progress (registration, readiness) inside the budgets below; the
    // readiness lag is widened because B can only follow through block sync.
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_BUILD_PROFILE", "release"),
        ("IOI_TEST_ORCH_RUST_LOG", "info,quv=debug,network=debug"),
        ("IOI_TEST_VALIDATOR_LAUNCH_CONCURRENCY", "2"),
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "64"),
        ("IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS", "180"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "10"),
        ("IOI_TEST_SIGNER_STARTUP_TIMEOUT_SECS", "120"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "500"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);
    let mut builder = TestCluster::builder()
        .with_validators(4)
        .with_consensus_type("Aft")
        .with_aft_safety_mode(AftSafetyMode::ClassicBft)
        .with_pq_consensus_profile()
        .with_validator_pqc_keypairs(fixture_pq_keys)
        .with_validator_orchestration_env(
            CLAIMANT_INDEX,
            "IOI_TESTING_AFT_STATUS_CLAIMED_ACCOUNT_HEX",
            &claimed_hex,
        )
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
    let build_started = Instant::now();
    let cluster = builder.build().await?;
    let build_elapsed_ms = build_started.elapsed().as_millis();
    let operation_starts = QuvOperationStartLog::drain(&cluster);
    // Post-build window only; the component logs retained by the runner cover
    // the launch window (B's first status response) for the evidence checker.
    let network_events = NetworkEventLog::drain(
        &cluster,
        &[
            "testing_status_account_override",
            "testing_status_account_override_invalid",
            "pq_peer_enrollment_refused",
            "pq_handoff_peer_enrollment_refused",
            "pq_provisional_enrollment_lost",
            "pq_carrier_authenticated",
        ],
    );
    let run = async {
        let members = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(index, guard)| {
                let key = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing ML-DSA fixture key"))?
                    .clone();
                let account = AccountId(account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &key.public_key().to_bytes(),
                )?);
                Ok((account, index, key))
            })
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(
            members[CLAIMED_INDEX].0 == claimed_account && members[CLAIMANT_INDEX].0 == claimant_account,
            "fixture keys were not installed in validator order"
        );
        let mut sorted = members.clone();
        sorted.sort_by_key(|entry| entry.0);
        let configured = sorted.iter().map(|entry| entry.0).collect::<HashSet<_>>();
        let active_set = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 4,
            validators: sorted
                .iter()
                .map(|entry| ValidatorV1 {
                    account_id: entry.0,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: entry.0 .0,
                        since_height: 0,
                    },
                })
                .collect(),
        };
        let configuration =
            ioi_types::app::canonical_validator_set_hash(&active_set).map_err(anyhow::Error::msg)?;
        let network = ioi_crypto::algorithms::hash::sha256(cluster.genesis_content.as_bytes())?;
        let claimed_key = &members[CLAIMED_INDEX].2;
        let claimed_rpc = cluster.validators[CLAIMED_INDEX].validator().rpc_addr.clone();
        let peer_of = |index: usize| {
            cluster.validators[index]
                .validator()
                .keypair
                .public()
                .to_peer_id()
                .to_string()
        };
        let claimed_peer = peer_of(CLAIMED_INDEX);
        let claimant_peer = peer_of(CLAIMANT_INDEX);

        // Every manifest is bound to C's endpoint key and runs on C's executor.
        let mut manifests = Vec::new();
        let mut warmups = Vec::new();
        for (index, name) in warmup_names.iter().enumerate() {
            let manifest = m16q_effect_manifest(
                &format!("status-squat-warmup-{}", index + 1),
                &format!("resource://aft-e2e/status-squat/warmup-{}", index + 1),
                name,
                1,
                warmup_roots[index],
                configuration,
                claimed_key,
                160 + index as u8,
            )?;
            let candidate = m16q_candidate(
                &manifest, network, configuration, warmup_roots[index], warmup_domains[index],
                claimed_account, claimed_key,
            )?;
            manifests.push(manifest.clone());
            warmups.push((manifest, candidate));
        }
        let measured = m16q_effect_manifest(
            "status-squat-measured",
            "resource://aft-e2e/status-squat/measured",
            measured_name,
            1,
            measured_root,
            configuration,
            claimed_key,
            170,
        )?;
        let measured_candidate = m16q_candidate(
            &measured, network, configuration, measured_root, measured_domain, claimed_account, claimed_key,
        )?;
        manifests.push(measured.clone());
        println!(
            "[M16Q-STATUS-SQUAT-EXPECT] first_contact=true configuration={} network={} claimed_account={claimed_hex} claimant_account={} claimed_process={CLAIMED_INDEX} claimant_process={CLAIMANT_INDEX} claimed_peer={claimed_peer} claimant_peer={claimant_peer} measured_domain={} manifests={} build_elapsed_ms={build_elapsed_ms}",
            hex::encode(configuration),
            hex::encode(network),
            hex::encode(claimant_account.as_ref()),
            hex::encode(measured_domain),
            manifests.len(),
        );

        // Registration: one manifest per block; wait for each commit and then
        // for admission of the last committed height on every process. B
        // follows only through block sync, so its wait is the most generous.
        let registration_rpc = claimed_rpc.clone();
        let mut last_committed_height: Option<u64> = None;
        for (nonce, manifest) in manifests.iter().enumerate() {
            let tx = signed_system_transaction(
                &cluster.validators[CLAIMED_INDEX].validator().keypair,
                SystemPayload::CallService {
                    service_id: AFT_EFFECT_REGISTRY_SERVICE_ID.into(),
                    method: REGISTER_AFT_EFFECT_MANIFEST_V1_METHOD.into(),
                    params: serde_jcs::to_vec(manifest)?,
                },
                nonce as u64,
                CHAIN_ID.into(),
            )?;
            let profile = rpc::submit_transaction_profiled(&registration_rpc, &tx).await?;
            if let Some(height) = profile.committed_height {
                last_committed_height =
                    Some(last_committed_height.map_or(height, |known| known.max(height)));
            }
        }
        let last_committed_height = last_committed_height
            .ok_or_else(|| anyhow::anyhow!("status-squat fixture observed no committed registration height"))?;
        let admitted_height = last_committed_height.saturating_add(2);
        for (index, guard) in cluster.validators.iter().enumerate() {
            let budget = if index == CLAIMANT_INDEX { 300 } else { 120 };
            wait_for_height(&guard.validator().rpc_addr, admitted_height, Duration::from_secs(budget)).await?;
        }
        println!(
            "[M16Q-STATUS-SQUAT-REGISTRATION] manifests={} last_committed_height={last_committed_height} admitted_height={admitted_height}",
            manifests.len()
        );

        let execute = |manifest: &EffectManifestV1, candidate: &QuvCandidateV0| {
            let rpc_addr = claimed_rpc.clone();
            let effect_id = manifest.effect_id.clone();
            let candidate = candidate.clone();
            async move {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    rpc::execute_aft_quv_effect(&rpc_addr, &effect_id, &candidate),
                )
                .await
                .map_err(|_| anyhow::anyhow!("effect {effect_id} exceeded its 30s client budget"))
            }
        };
        // Which configured members replied, straight from the checked audit
        // evidence; used for the recorded warm-up rows and the diagnostic row
        // printed before the measured assertion.
        let observed_members = |response: &ioi_ipc::public::ExecuteAftQuvEffectResponse| -> Result<Vec<AccountId>> {
            let receipt: ConsequenceReceiptV1 = serde_json::from_slice(&response.consequence_receipt_jcs)?;
            let audit = receipt
                .online_authorization_audit
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("executed consequence omitted its live QUV audit"))?;
            let evidence: QuvAcceptedAuditEvidenceV0 =
                codec::from_bytes_canonical(&audit.protocol_evidence).map_err(anyhow::Error::msg)?;
            Ok(evidence.valid_replies.iter().map(|reply| reply.member).collect())
        };
        let member_list = |accounts: &[AccountId]| {
            let mut names = accounts.iter().map(|account| hex::encode(account.as_ref())).collect::<Vec<_>>();
            names.sort();
            names.join(",")
        };

        // Ruling (2026-09-06): the claimant is Byzantine by construction. It
        // never presents its own account, so no peer can bind its carrier and
        // its own reply is not owed under the theorem; every CORRECT member's
        // reply is. The expected valid set is therefore configured minus the
        // claimant, exactly.
        let expected_valid = configured
            .iter()
            .copied()
            .filter(|account| *account != claimant_account)
            .collect::<HashSet<_>>();
        anyhow::ensure!(expected_valid.len() == configured.len() - 1);

        // Warm-up: cold-lane cost is recorded, never asserted; the expected
        // outcome is exactly the expected valid set, and a second fresh
        // warm-up domain is used only if the first did not reach it.
        let mut warmup_attempts = 0_u32;
        for (slot, (manifest, candidate)) in warmups.iter().enumerate() {
            warmup_attempts += 1;
            let started = Instant::now();
            let outcome = execute(manifest, candidate).await?;
            let elapsed_ms = started.elapsed().as_millis();
            let expected_coverage = match outcome {
                Ok(response) => {
                    let replied = observed_members(&response)?;
                    let coverage = require_executed_nonportable_quv_receipt(&response, &configured, &expected_valid);
                    println!(
                        "[M16Q-STATUS-SQUAT-WARMUP] attempt={warmup_attempts} slot={} outcome={} members_valid={} valid_members={} elapsed_ms={elapsed_ms}",
                        slot + 1,
                        if coverage.is_ok() { "executed_expected_coverage" } else { "executed_unexpected_coverage" },
                        replied.len(),
                        member_list(&replied),
                    );
                    coverage.is_ok()
                }
                Err(error) => {
                    println!(
                        "[M16Q-STATUS-SQUAT-WARMUP] attempt={warmup_attempts} slot={} outcome=aborted members_valid=0 valid_members= elapsed_ms={elapsed_ms} error={:?}",
                        slot + 1,
                        format!("{error:#}"),
                    );
                    false
                }
            };
            if expected_coverage {
                break;
            }
        }

        // Measured operation on C's executor under the live first-contact claim.
        let starts_before = operation_starts.len();
        let events_before = network_events.len();
        let started = Instant::now();
        let response = execute(&measured, &measured_candidate).await??;
        let elapsed_ms = started.elapsed().as_millis();
        let replied = observed_members(&response)?;
        println!(
            "[M16Q-STATUS-SQUAT-OBSERVED] members_configured={} members_valid={} valid_members={} claimed_replied={} claimant_replied={} elapsed_ms={elapsed_ms}",
            configured.len(),
            replied.len(),
            member_list(&replied),
            replied.contains(&claimed_account),
            replied.contains(&claimant_account),
        );
        // Exactly the correct members replied: C's own reply and both genuine
        // third members, never the claimant. Losing C's reply is a real
        // finding; a fourth reply would mean the squatter got bound.
        let max_valid_reply_elapsed_ms =
            require_executed_nonportable_quv_receipt(&response, &configured, &expected_valid)?;
        if !replied.contains(&claimed_account) || replied.contains(&claimant_account) {
            return Err(anyhow::anyhow!(
                "status-squat reply set is inconsistent: claimed_replied={} claimant_replied={}",
                replied.contains(&claimed_account),
                replied.contains(&claimant_account),
            ));
        }
        let executor_starts = operation_starts
            .since(starts_before)?
            .iter()
            .filter(|start| start.process_index == CLAIMED_INDEX && !start.independent_preparation)
            .count();
        if executor_starts != 1 {
            return Err(anyhow::anyhow!(
                "measured operation started {executor_starts} executor operation(s) on C, expected 1"
            ));
        }

        // Post-build log window: B keeps claiming C on every periodic status
        // response; every other process keeps refusing or dropping that claim;
        // B is never authenticated under C's account; no malformed override.
        let events = network_events.since(0)?;
        let overrides = events
            .iter()
            .filter(|record| {
                record.event == "testing_status_account_override"
                    && record.process_index == CLAIMANT_INDEX
                    && record.claimed_account.as_deref() == Some(claimed_hex.as_str())
                    && record.local_peer.as_deref() == Some(claimant_peer.as_str())
            })
            .count();
        let foreign_overrides = events
            .iter()
            .filter(|record| {
                record.event.starts_with("testing_status_account_override")
                    && record.process_index != CLAIMANT_INDEX
            })
            .count();
        let invalid_overrides = events
            .iter()
            .filter(|record| record.event == "testing_status_account_override_invalid")
            .count();
        let mut refusing_processes = HashSet::new();
        let mut refusal_reasons = std::collections::BTreeSet::new();
        for record in events.iter().filter(|record| {
            record.process_index != CLAIMANT_INDEX
                && record.peer.as_deref() == Some(claimant_peer.as_str())
                && matches!(
                    record.event.as_str(),
                    "pq_peer_enrollment_refused" | "pq_handoff_peer_enrollment_refused" | "pq_provisional_enrollment_lost"
                )
        }) {
            refusing_processes.insert(record.process_index);
            refusal_reasons.insert(format!(
                "{}:{}",
                record.event,
                record.error.as_deref().unwrap_or("-").replace(' ', "_")
            ));
        }
        let refusal_reasons = refusal_reasons.into_iter().collect::<Vec<_>>().join("|");
        // The claimant must never be authenticated under ANY account on any
        // process (post-build window here; the component-log checker covers
        // the launch window, the override-before-first-response order and
        // the claimed carrier's authentication on the genuine third
        // processes, which precede this drain).
        let claimant_authenticated_any = events
            .iter()
            .filter(|record| {
                record.event == "pq_carrier_authenticated"
                    && record.peer.as_deref() == Some(claimant_peer.as_str())
            })
            .count();
        let expected_refusers = (0..cluster.validators.len())
            .filter(|index| *index != CLAIMANT_INDEX)
            .collect::<HashSet<_>>();
        let events_during_measured = events.len().saturating_sub(events_before);
        if overrides < 1
            || foreign_overrides != 0
            || invalid_overrides != 0
            || refusing_processes != expected_refusers
            || claimant_authenticated_any != 0
        {
            return Err(anyhow::anyhow!(
                "status-squat evidence incomplete: overrides={overrides} foreign_overrides={foreign_overrides} invalid_overrides={invalid_overrides} refusing_processes={refusing_processes:?} claimant_authenticated_any={claimant_authenticated_any}"
            ));
        }
        println!(
            "[M16Q-STATUS-SQUAT] first_contact=true claimed_account={claimed_hex} claimant_process={CLAIMANT_INDEX} claimant_peer={claimant_peer} members_configured={} members_valid={} claimant_excluded=true claimed_replied=true override_warnings={overrides} refusing_processes={} refusal_reasons={refusal_reasons} claimant_authenticated_any=0 warmup_attempts={warmup_attempts} events_during_measured={events_during_measured} elapsed_ms={elapsed_ms} max_valid_reply_elapsed_ms={max_valid_reply_elapsed_ms} qualified_envelope_ms={QUALIFIED_ENVELOPE_MS} result=executed",
            configured.len(),
            replied.len(),
            refusing_processes.len(),
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    operation_starts.stop();
    network_events.stop();
    let shutdown = cluster.shutdown().await;
    run?;
    shutdown?;
    Ok(())
}
