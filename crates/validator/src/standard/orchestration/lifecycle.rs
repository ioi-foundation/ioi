use super::*;

impl<CS, ST, CE, V> Orchestrator<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Clone
        + Debug,
    CE: ConsensusEngine<ChainTransaction> + ConsensusControl + Send + Sync + 'static, // [FIX] Added ConsensusControl bound
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    async fn perform_guardian_attestation(
        &self,
        guardian_addr: &str,
        workload_client: &WorkloadClient,
    ) -> Result<()> {
        let guardian_channel =
            ioi_client::security::SecurityChannel::new("orchestration", "guardian");
        let certs_dir = std::env::var("CERTS_DIR").map_err(|_| {
            ValidatorError::Config("CERTS_DIR environment variable must be set".to_string())
        })?;
        guardian_channel
            .establish_client(
                guardian_addr,
                "guardian",
                &format!("{}/ca.pem", certs_dir),
                &format!("{}/orchestration.pem", certs_dir),
                &format!("{}/orchestration.key", certs_dir),
            )
            .await?;

        let mut stream = guardian_channel
            .take_stream()
            .await
            .ok_or_else(|| anyhow!("Failed to take stream from Guardian channel"))?;

        let len = stream.read_u32().await?;
        const MAX_REPORT_SIZE: u32 = 10 * 1024 * 1024;
        if len > MAX_REPORT_SIZE {
            return Err(anyhow!(
                "Guardian attestation report too large: {} bytes (limit: {})",
                len,
                MAX_REPORT_SIZE
            ));
        }

        let mut report_bytes = vec![0u8; len as usize];
        stream.read_exact(&mut report_bytes).await?;

        let report: GuardianReport = serde_json::from_slice(&report_bytes)
            .map_err(|e| anyhow!("Failed to deserialize Guardian report: {}", e))?;

        let expected_hash = workload_client.get_expected_model_hash().await?;
        if report.agentic_hash != expected_hash {
            return Err(anyhow!(
                "Model Integrity Failure! Local hash {} != on-chain hash {}",
                hex::encode(&report.agentic_hash),
                hex::encode(expected_hash)
            ));
        }

        let payload_bytes =
            codec::to_bytes_canonical(&report.binary_attestation).map_err(|e| anyhow!(e))?;

        let sys_payload = SystemPayload::CallService {
            service_id: "identity_hub".to_string(),
            method: "register_attestation@v1".to_string(),
            params: payload_bytes,
        };

        let our_pk = self.local_keypair.public().encode_protobuf();
        let our_account_id = AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &our_pk)
                .map_err(|e| anyhow!(e))?,
        );

        let nonce = {
            let mut nm = self.nonce_manager.lock().await;
            let n = nm.entry(our_account_id).or_insert(0);
            let cur = *n;
            *n += 1;
            cur
        };

        let mut sys_tx = SystemTransaction {
            header: SignHeader {
                account_id: our_account_id,
                nonce,
                chain_id: self.config.chain_id,
                tx_version: 1,
                session_auth: None,
            },
            payload: sys_payload,
            signature_proof: SignatureProof::default(),
        };

        let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
        let signature = self.local_keypair.sign(&sign_bytes)?;

        sys_tx.signature_proof = SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: our_pk,
            signature,
        };

        let tx = ChainTransaction::System(Box::new(sys_tx));
        let tx_hash = tx.hash()?;

        let committed_nonce = 0;
        self.tx_pool
            .add(tx, tx_hash, Some((our_account_id, nonce)), committed_nonce);

        Ok(())
    }

    async fn run_consensus_ticker(
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
        mut kick_rx: mpsc::UnboundedReceiver<()>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        // [INSTRUMENTATION] Log ticker start
        tracing::info!(target: "consensus", "DEBUG: Consensus ticker thread spawned.");

        let interval_secs = {
            let ctx = context_arc.lock().await;
            std::env::var("ORCH_BLOCK_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| ctx.config.block_production_interval_secs)
        };
        tracing::info!(target: "consensus", "DEBUG: Consensus Ticker interval: {}s", interval_secs);

        if interval_secs == 0 {
            tracing::info!(target: "consensus", "Consensus ticker disabled (interval=0).");
            let _ = shutdown_rx.changed().await;
            return;
        }

        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let min_block_time = Duration::from_millis(50);
        let mut last_tick = tokio::time::Instant::now()
            .checked_sub(min_block_time)
            .unwrap();

        // Track the epoch we last saw
        let mut last_seen_epoch = 0;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // [FIX] Split lock and clone to avoid holding lock across await or creating temporary with bad lifetime
                    let (is_quarantined, node_state) = {
                        let ctx = context_arc.lock().await;
                        let q = ctx.is_quarantined.load(Ordering::SeqCst);
                        let ns = ctx.node_state.lock().await.clone();
                        (q, ns)
                    };

                    if is_quarantined { continue; }

                    // [NEW] Lazarus Recovery Check
                    if node_state == NodeState::SurvivalMode {
                         // Poll for epoch change
                         let client = { context_arc.lock().await.view_resolver.workload_client().clone() };
                         let key = ioi_types::keys::CURRENT_EPOCH_KEY;

                         if let Ok(Some(bytes)) = client.query_raw_state(key).await {
                             if let Ok(current_epoch) = ioi_types::codec::from_bytes_canonical::<u64>(&bytes) {
                                 if current_epoch > last_seen_epoch {
                                     tracing::info!(target: "orchestration", "Lazarus Recovery: Epoch {} detected (was {}). Restoring A-DMFT.", current_epoch, last_seen_epoch);
                                     last_seen_epoch = current_epoch;

                                     let ctx = context_arc.lock().await;
                                     *ctx.node_state.lock().await = NodeState::Synced;

                                     // Switch Engine back to A-DMFT
                                     let mut engine = ctx.consensus_engine_ref.lock().await;
                                     engine.switch_to_admft();

                                     // Resume normal operation
                                     continue;
                                 }
                             }
                         }

                         // Continue A-PMFT sampling loop while in Survival Mode
                         let cause = "apmft_tick";
                         // A-PMFT decide will trigger sampling (Stall with sampling side-effects or a new Decision)
                         // Currently engine returns Stall, but events loop drives sampling.
                         // But we should call decide() to allow state machine to update round/preference.
                         let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                         if let Err(e) = result.map_err(|e| anyhow!("A-PMFT tick panicked: {:?}", e)).and_then(|res| res) {
                            tracing::error!(target: "consensus", "[Orch Tick] A-PMFT tick failed: {:?}.", e);
                         }
                    } else {
                         // Standard A-DMFT
                        last_tick = tokio::time::Instant::now();

                        // [INSTRUMENTATION] Log tick trigger
                        tracing::info!(target: "consensus", "Consensus timer tick triggered.");

                        let cause = "timer";
                        let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                        if let Err(e) = result.map_err(|e| anyhow!("Consensus tick panicked: {:?}", e)).and_then(|res| res) {
                            tracing::error!(target: "consensus", "[Orch Tick] Consensus tick failed: {:?}. Continuing loop.", e);
                        }
                    }
                }
                Some(()) = kick_rx.recv() => {
                    let mut _count = 1;
                    while let Ok(_) = kick_rx.try_recv() { _count += 1; }
                    let cause = "kick";
                    let is_quarantined = context_arc.lock().await.is_quarantined.load(Ordering::SeqCst);
                    if is_quarantined || last_tick.elapsed() < min_block_time {
                         continue;
                    }
                    last_tick = tokio::time::Instant::now();

                    // [INSTRUMENTATION] Log kick trigger
                    tracing::debug!(target: "consensus", "Consensus kicked.");

                    let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                     if let Err(e) = result.map_err(|e| anyhow!("Kicked consensus tick panicked: {:?}", e)).and_then(|res| res) {
                        tracing::error!(target: "consensus", "[Orch Tick] Kicked failed: {:?}.", e);
                    }
                }
                 _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
            }
        }
    }

    async fn run_sync_discoverer(
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let interval_secs = {
            let ctx = context_arc.lock().await;
            ctx.config.initial_sync_timeout_secs
        };

        if interval_secs == 0 {
            tracing::info!(target: "orchestration", "Sync discoverer disabled (interval=0).");
            let _ = shutdown_rx.changed().await;
            return;
        }

        let mut interval = time::interval(Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let (known_peers, swarm_commander) = {
                        let ctx = context_arc.lock().await;
                        (ctx.known_peers_ref.clone(), ctx.swarm_commander.clone())
                    };
                    let random_peer_opt = {
                        let peers: Vec<_> = known_peers.lock().await.iter().cloned().collect();
                        peers.choose(&mut rand::thread_rng()).cloned()
                    };
                    if let Some(random_peer) = random_peer_opt {
                        if swarm_commander.send(SwarmCommand::SendStatusRequest(random_peer)).await.is_err() {
                            log::warn!("Failed to send periodic status request to swarm.");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
            }
        }
    }

    async fn run_main_loop(
        mut network_event_receiver: mpsc::Receiver<NetworkEvent>,
        mut shutdown_receiver: watch::Receiver<bool>,
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    ) {
        let sync_timeout = {
            let ctx = context_arc.lock().await;
            ctx.config.initial_sync_timeout_secs
        };

        if sync_timeout == 0 {
            let context = context_arc.lock().await;
            let mut ns = context.node_state.lock().await;
            if *ns == NodeState::Syncing || *ns == NodeState::Initializing {
                *ns = NodeState::Synced;
                let _ = context.consensus_kick_tx.send(());
                tracing::info!(target: "orchestration", "State -> Synced (direct/local mode).");
            }
        } else {
            let context = context_arc.lock().await;
            *context.node_state.lock().await = NodeState::Syncing;
            tracing::info!(target: "orchestration", "State -> Syncing.");
        }

        let mut sync_check_interval_opt = if sync_timeout > 0 {
            let mut i = time::interval(Duration::from_secs(sync_timeout));
            i.set_missed_tick_behavior(MissedTickBehavior::Delay);
            Some(i)
        } else {
            None
        };

        let mut operator_ticker = time::interval(Duration::from_secs(10));
        operator_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                Some(event) = network_event_receiver.recv() => {
                    handle_network_event(event, &context_arc).await;
                }

                _ = operator_ticker.tick() => {
                    let ctx = context_arc.lock().await;
                    if let Err(e) = run_oracle_operator_task(&ctx).await {
                         tracing::error!(target: "operator_task", "Oracle operator failed: {}", e);
                    }
                }

                _ = async {
                    if let Some(ref mut i) = sync_check_interval_opt {
                        i.tick().await
                    } else {
                        futures::future::pending().await
                    }
                }, if *context_arc.lock().await.node_state.lock().await == NodeState::Syncing => {
                    let context = context_arc.lock().await;
                    if context.known_peers_ref.lock().await.is_empty() {
                        let mut node_state = context.node_state.lock().await;
                        if *node_state == NodeState::Syncing {
                            *node_state = NodeState::Synced;
                            let _ = context.consensus_kick_tx.send(());
                            tracing::info!(target: "orchestration", "State -> Synced (no peers).");
                        }
                    }
                },

                _ = shutdown_receiver.changed() => {
                    if *shutdown_receiver.borrow() { break; }
                }
            }
        }
    }

    pub(crate) async fn start_internal(&self, _listen_addr: &str) -> Result<(), ValidatorError> {
        if self.is_running.load(Ordering::SeqCst) {
            return Err(ValidatorError::AlreadyRunning("orchestration".to_string()));
        }
        tracing::info!(target: "orchestration", "Orchestrator starting...");

        self.syncer
            .start()
            .await
            .map_err(|e| ValidatorError::Other(e.to_string()))?;

        let workload_client = self
            .workload_client
            .get()
            .ok_or_else(|| {
                ValidatorError::Other(
                    "Workload client ref not initialized before start".to_string(),
                )
            })?
            .clone();

        // --- NEW: Hydrate Chain Tip from Store ---
        let mut initial_block = None;
        match workload_client.get_status().await {
            Ok(status) => {
                if status.height > 0 {
                    tracing::info!(target: "orchestration", "Recovering chain state from height {}", status.height);
                    match workload_client.get_block_by_height(status.height).await {
                        Ok(Some(block)) => {
                            initial_block = Some(block);
                            tracing::info!(target: "orchestration", "Hydrated last_committed_block (Height {})", status.height);
                        }
                        Ok(None) => {
                            tracing::warn!(target: "orchestration", "Status says height {}, but block not found in store!", status.height);
                        }
                        Err(e) => {
                            tracing::error!(target: "orchestration", "Failed to fetch head block: {}", e);
                            return Err(ValidatorError::Other(e.to_string()));
                        }
                    }
                }
            }
            Err(e) => {
                return Err(ValidatorError::Other(format!(
                    "Failed to get initial chain status: {}",
                    e
                )));
            }
        }
        // ------------------------------------------

        let tx_model = Arc::new(UnifiedTransactionModel::new(self.scheme.clone()));
        let (tx_ingest_tx, tx_ingest_rx) = mpsc::channel(50_000);

        let initial_tip = if let Some(b) = &initial_block {
            ChainTipInfo {
                height: b.header.height,
                timestamp: b.header.timestamp,
                gas_used: b.header.gas_used,
                state_root: b.header.state_root.0.clone(),
                genesis_root: self.genesis_hash.to_vec(),
            }
        } else {
            ChainTipInfo {
                height: 0,
                timestamp: 0,
                gas_used: 0,
                state_root: vec![],
                genesis_root: self.genesis_hash.to_vec(),
            }
        };

        let (tip_tx, tip_rx) = watch::channel(initial_tip);
        let tx_status_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(100_000).unwrap(),
        )));
        let receipt_map = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(100_000).unwrap(),
        )));
        let public_service = PublicApiImpl {
            context_wrapper: self.main_loop_context.clone(),
            workload_client: workload_client.clone(),
            tx_ingest_tx,
        };

        let rpc_addr = self
            .config
            .rpc_listen_address
            .parse()
            .map_err(|e| ValidatorError::Config(format!("Invalid RPC address: {}", e)))?;

        tracing::info!(target: "rpc", "Public gRPC API listening on {}", rpc_addr);
        eprintln!("ORCHESTRATION_RPC_LISTENING_ON_{}", rpc_addr);

        let mut shutdown_rx = self.shutdown_sender.subscribe();

        let rpc_handle = tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .add_service(PublicApiServer::new(public_service))
                .serve_with_shutdown(rpc_addr, async move {
                    let _ = shutdown_rx.changed().await;
                })
                .await
            {
                tracing::error!(target: "rpc", "Public API server failed: {}", e);
            }
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(rpc_handle);

        let (event_tx, _event_rx_guard) = if let Some(tx) = &self.event_broadcaster {
            (tx.clone(), None)
        } else {
            let (tx, rx) = tokio::sync::broadcast::channel(1000);
            (tx, Some(rx))
        };

        let ingestion_handle = tokio::spawn(run_ingestion_worker(
            tx_ingest_rx,
            workload_client.clone(),
            self.tx_pool.clone(),
            self.swarm_command_sender.clone(),
            self.consensus_kick_tx.clone(),
            tx_model.clone(),
            tip_rx,
            tx_status_cache.clone(),
            receipt_map.clone(),
            self.safety_model.clone(),
            self.os_driver.clone(),
            IngestionConfig::default(),
            event_tx.clone(),
        ));
        handles.push(ingestion_handle);

        let guardian_addr = std::env::var("GUARDIAN_ADDR").unwrap_or_default();
        if !guardian_addr.is_empty() {
            tracing::info!(target: "orchestration", "[Orchestration] Performing agentic attestation with Guardian...");
            match self
                .perform_guardian_attestation(&guardian_addr, &workload_client)
                .await
            {
                Ok(()) => {
                    tracing::info!(target: "orchestration", "[Orchestrator] Agentic attestation successful.")
                }
                Err(e) => {
                    tracing::error!(target: "orchestration", "[Orchestrator] CRITICAL: Agentic attestation failed: {}. Quarantining node.", e);
                    self.is_quarantined.store(true, Ordering::SeqCst);
                    return Err(ValidatorError::Attestation(e.to_string()));
                }
            }
        }

        let chain = self
            .chain
            .get()
            .ok_or_else(|| {
                ValidatorError::Other("Chain ref not initialized before start".to_string())
            })?
            .clone();

        let view_resolver = Arc::new(view_resolver::DefaultViewResolver::new(
            workload_client.clone(),
            self.verifier.clone(),
            self.proof_cache.clone(),
        ));

        let local_account_id = AccountId(
            account_id_from_key_material(
                SignatureSuite::ED25519,
                &self.local_keypair.public().encode_protobuf(),
            )
            .map_err(|e| {
                ValidatorError::Config(format!("Failed to derive local account ID: {}", e))
            })?,
        );
        let nonce_key = [
            ioi_types::keys::ACCOUNT_NONCE_PREFIX,
            local_account_id.as_ref(),
        ]
        .concat();

        let initial_nonce = match workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(bytes)) => {
                let arr: [u8; 8] = match bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => [0; 8],
                };
                u64::from_le_bytes(arr)
            }
            _ => 0,
        };
        self.nonce_manager
            .lock()
            .await
            .insert(local_account_id, initial_nonce);

        let context = MainLoopContext::<CS, ST, CE, V> {
            chain_ref: chain,
            tx_pool_ref: self.tx_pool.clone(),
            view_resolver,
            swarm_commander: self.swarm_command_sender.clone(),
            consensus_engine_ref: self.consensus_engine.clone(),
            node_state: self.syncer.get_node_state(),
            local_keypair: self.local_keypair.clone(),
            pqc_signer: self.pqc_signer.clone(),
            known_peers_ref: self.syncer.get_known_peers(),
            config: self.config.clone(),
            chain_id: self.config.chain_id,
            genesis_hash: self.genesis_hash,
            is_quarantined: self.is_quarantined.clone(),
            pending_attestations: std::collections::HashMap::new(),
            last_committed_block: initial_block,
            consensus_kick_tx: self.consensus_kick_tx.clone(),
            sync_progress: None,
            nonce_manager: self.nonce_manager.clone(),
            signer: self.signer.clone(),
            batch_verifier: self.batch_verifier.clone(),
            tx_status_cache: tx_status_cache.clone(),
            tip_sender: tip_tx,
            receipt_map: receipt_map.clone(),
            safety_model: self.safety_model.clone(),
            inference_runtime: Arc::new(RuntimeWrapper {
                inner: self.inference_runtime.clone(),
            }),
            os_driver: self.os_driver.clone(),
            scs: self.scs.clone(),
            event_broadcaster: event_tx,
        };

        let mut receiver_opt = self.network_event_receiver.lock().await;
        let receiver = receiver_opt.take().ok_or(ValidatorError::Other(
            "Network event receiver already taken".to_string(),
        ))?;

        let context_arc = Arc::new(Mutex::new(context));
        *self.main_loop_context.lock().await = Some(context_arc.clone());

        let ticker_kick_rx = match self.consensus_kick_rx.lock().await.take() {
            Some(rx) => rx,
            None => {
                return Err(ValidatorError::Other(
                    "Consensus kick receiver already taken".into(),
                ))
            }
        };

        let shutdown_rx = self.shutdown_sender.subscribe();

        handles.push(tokio::spawn(Self::run_consensus_ticker(
            context_arc.clone(),
            ticker_kick_rx,
            shutdown_rx.clone(),
        )));
        handles.push(tokio::spawn(Self::run_sync_discoverer(
            context_arc.clone(),
            shutdown_rx.clone(),
        )));
        handles.push(tokio::spawn(
            crate::standard::orchestration::operator_tasks::run_wallet_network_audit_bridge_task(
                context_arc.clone(),
                shutdown_rx.clone(),
            ),
        ));
        handles.push(tokio::spawn(Self::run_main_loop(
            receiver,
            shutdown_rx,
            context_arc,
        )));

        self.is_running.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub(crate) async fn stop_internal(&self) -> Result<(), ValidatorError> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Ok(());
        }
        tracing::info!(target: "orchestration", "Orchestrator stopping...");
        self.shutdown_sender.send(true).ok();

        tokio::time::sleep(Duration::from_millis(100)).await;

        self.is_running.store(false, Ordering::SeqCst);

        self.syncer
            .stop()
            .await
            .map_err(|e| ValidatorError::Other(e.to_string()))?;

        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle
                .await
                .map_err(|e| ValidatorError::Other(format!("Task panicked: {e}")))?;
        }
        Ok(())
    }
}
