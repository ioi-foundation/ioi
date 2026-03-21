impl GuardianContainer {
    /// Creates a new Guardian container instance.
    pub fn new(
        config_dir: PathBuf,
        config: GuardianConfig,
        validator_account_id: AccountId,
    ) -> Result<Self> {
        let key_authority: Arc<dyn KeyAuthority> = Arc::from(build_key_authority(
            config.key_authority.clone(),
            config.production_mode,
        )?);
        let default_transparency_log_id = if config.transparency_log.log_id.trim().is_empty() {
            if config.committee.transparency_log_id.trim().is_empty() {
                "guardian-local".to_string()
            } else {
                config.committee.transparency_log_id.clone()
            }
        } else {
            config.transparency_log.log_id.clone()
        };
        let transparency_log_signer = load_transparency_log_signer(&config)?;
        let transparency_log_signer_bytes = transparency_log_signer
            .to_protobuf_encoding()
            .map_err(|e| anyhow!("failed to encode transparency log signer: {e}"))?;
        let transparency_logs = collect_transparency_log_ids(&config)
            .into_iter()
            .map(|log_id| {
                let signer = libp2p::identity::Keypair::from_protobuf_encoding(
                    &transparency_log_signer_bytes,
                )
                .map_err(|e| anyhow!("failed to decode transparency log signer: {e}"))?;
                Ok::<_, anyhow::Error>((
                    log_id.clone(),
                    Arc::new(MemoryTransparencyLog::new(log_id, signer))
                        as Arc<dyn TransparencyLog>,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let committee_client = GuardianCommitteeClient::from_config(&config, validator_account_id)?;
        let witness_committee_clients = GuardianWitnessCommitteeClient::from_configs(&config)?;
        Ok(Self {
            orchestration_channel: SecurityChannel::new("guardian", "orchestration"),
            workload_channel: SecurityChannel::new("guardian", "workload"),
            is_running: Arc::new(AtomicBool::new(false)),
            config_dir,
            key_authority,
            transparency_logs,
            default_transparency_log_id,
            verifier_policy: config.verifier_policy.clone(),
            production_mode: config.production_mode,
            committee_client,
            witness_committee_clients,
            decision_state: Arc::new(TokioMutex::new(GuardianDecisionState::default())),
            sealed_effect_nullifiers: Arc::new(TokioMutex::new(BTreeSet::new())),
            observer_rpc_channels: Arc::new(TokioMutex::new(HashMap::new())),
        })
    }

    fn transparency_log_for(&self, log_id: &str) -> Result<Arc<dyn TransparencyLog>> {
        self.transparency_logs
            .get(log_id)
            .cloned()
            .ok_or_else(|| anyhow!("guardian transparency log '{log_id}' is not configured"))
    }

    fn default_transparency_log(&self) -> Result<Arc<dyn TransparencyLog>> {
        self.transparency_log_for(&self.default_transparency_log_id)
    }

    fn assigned_recovery_share_store_root(&self) -> PathBuf {
        self.config_dir.join("recovery_shares").join("v1")
    }

    fn assigned_recovery_share_envelope_path(
        &self,
        witness_manifest_hash: [u8; 32],
        height: u64,
        recovery_binding: &GuardianWitnessRecoveryBinding,
    ) -> PathBuf {
        self.assigned_recovery_share_store_root()
            .join(hex::encode(witness_manifest_hash))
            .join(height.to_string())
            .join(format!(
                "{}-{}.scale",
                hex::encode(recovery_binding.recovery_capsule_hash),
                hex::encode(recovery_binding.share_commitment_hash)
            ))
    }

    fn verify_and_store_assigned_recovery_share_envelope(
        &self,
        statement: &GuardianWitnessStatement,
        witness_manifest_hash: [u8; 32],
        recovery_share_envelope: &AssignedRecoveryShareEnvelopeV1,
    ) -> Result<()> {
        let expected_binding = statement.recovery_binding.as_ref().ok_or_else(|| {
            anyhow!("assigned recovery share envelope requires a signed recovery binding")
        })?;
        recovery_share_envelope
            .validate_for_witness(witness_manifest_hash, statement.height)
            .map_err(anyhow::Error::msg)?;
        if recovery_share_envelope.recovery_binding() != *expected_binding {
            return Err(anyhow!(
                "assigned recovery share envelope does not match the signed recovery binding"
            ));
        }

        let path = self.assigned_recovery_share_envelope_path(
            witness_manifest_hash,
            statement.height,
            expected_binding,
        );
        let envelope_bytes = codec::to_bytes_canonical(recovery_share_envelope)
            .map_err(|e| anyhow!(e.to_string()))?;

        match std::fs::read(&path) {
            Ok(existing_bytes) => {
                if existing_bytes != envelope_bytes {
                    return Err(anyhow!(
                        "assigned recovery share envelope conflicts with an existing stored share"
                    ));
                }
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(&path)?;
        file.write_all(&envelope_bytes)?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn load_assigned_recovery_share_envelope(
        &self,
        witness_manifest_hash: [u8; 32],
        height: u64,
        recovery_binding: &GuardianWitnessRecoveryBinding,
    ) -> Result<Option<AssignedRecoveryShareEnvelopeV1>> {
        let path = self.assigned_recovery_share_envelope_path(
            witness_manifest_hash,
            height,
            recovery_binding,
        );
        let envelope_bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let envelope: AssignedRecoveryShareEnvelopeV1 =
            codec::from_bytes_canonical(&envelope_bytes).map_err(|e| anyhow!(e.to_string()))?;
        envelope
            .validate_for_witness(witness_manifest_hash, height)
            .map_err(anyhow::Error::msg)?;
        if envelope.recovery_binding() != *recovery_binding {
            return Err(anyhow!(
                "stored assigned recovery share envelope does not match the requested recovery binding"
            ));
        }
        Ok(Some(envelope))
    }

    /// Loads previously stored assigned recovery share material by witness binding.
    pub fn load_assigned_recovery_share_material(
        &self,
        witness_manifest_hash: [u8; 32],
        height: u64,
        recovery_binding: &GuardianWitnessRecoveryBinding,
    ) -> Result<Option<RecoveryShareMaterial>> {
        self.load_assigned_recovery_share_envelope(witness_manifest_hash, height, recovery_binding)
            .map(|envelope| envelope.map(|envelope| envelope.share_material))
    }

    async fn issue_guardian_quorum_certificate(
        &self,
        domain: GuardianDecisionDomain,
        slot: Option<(u64, u64)>,
        subject: Vec<u8>,
        payload_hash: [u8; 32],
        expected_counter: u64,
        expected_trace_hash: [u8; 32],
        requested_measurement_root: Option<[u8; 32]>,
        requested_policy_hash: Option<[u8; 32]>,
        requested_manifest_hash: Option<[u8; 32]>,
    ) -> Result<Option<(u64, [u8; 32], GuardianQuorumCertificate)>> {
        let Some(committee_client) = &self.committee_client else {
            return Ok(None);
        };

        if let Some(manifest_hash) = requested_manifest_hash.filter(|hash| *hash != [0u8; 32]) {
            if manifest_hash != committee_client.manifest_hash() {
                return Err(anyhow!(
                    "requested guardian manifest hash does not match local committee"
                ));
            }
        }

        let (prior_counter, prior_trace_hash, counter, trace_hash) = {
            let decision_state = self.decision_state.lock().await;
            if let Some(slot) = slot {
                if let Some(locked_payload_hash) = decision_state.slot_locks.get(&slot) {
                    if locked_payload_hash != &payload_hash {
                        return Err(anyhow!(
                            "guardian slot already certified for a different payload at height {} view {}",
                            slot.0,
                            slot.1
                        ));
                    }
                    if let Some(existing_certificate) =
                        decision_state.slot_certificates.get(&slot).cloned()
                    {
                        return Ok(Some((
                            existing_certificate.counter,
                            existing_certificate.trace_hash,
                            existing_certificate,
                        )));
                    }
                }
            }
            if expected_counter != 0 && expected_counter != decision_state.counter {
                return Err(anyhow!(
                    "guardian counter checkpoint mismatch: expected {}, current {}",
                    expected_counter,
                    decision_state.counter
                ));
            }
            if expected_trace_hash != [0u8; 32] && expected_trace_hash != decision_state.trace_hash
            {
                return Err(anyhow!("guardian trace checkpoint mismatch"));
            }
            let counter = decision_state.counter.saturating_add(1);
            let trace_hash = digest_to_array(
                Sha256::digest(
                    &[
                        decision_state.trace_hash.as_ref(),
                        payload_hash.as_ref(),
                        counter.to_be_bytes().as_ref(),
                        committee_client.manifest_hash().as_ref(),
                    ]
                    .concat(),
                )
                .map_err(|e| anyhow!(e))?,
            )?;
            (
                decision_state.counter,
                decision_state.trace_hash,
                counter,
                trace_hash,
            )
        };
        let decision = GuardianDecision {
            domain: domain as u8,
            subject: if subject.is_empty() {
                committee_client.default_subject()
            } else {
                subject
            },
            payload_hash,
            counter,
            trace_hash,
            measurement_root: requested_measurement_root
                .filter(|hash| *hash != [0u8; 32])
                .unwrap_or_else(|| committee_client.default_measurement_root()),
            policy_hash: requested_policy_hash
                .filter(|hash| *hash != [0u8; 32])
                .unwrap_or_else(|| committee_client.default_policy_hash()),
        };

        let transparency_log_id = if committee_client
            .manifest
            .transparency_log_id
            .trim()
            .is_empty()
        {
            self.default_transparency_log_id.clone()
        } else {
            committee_client.manifest.transparency_log_id.clone()
        };
        let transparency_log = self.transparency_log_for(&transparency_log_id)?;
        let mut certificate = committee_client.sign_decision(&decision, slot).await?;
        let checkpoint_payload = codec::to_bytes_canonical(&(&decision, &certificate))
            .map_err(|e| anyhow!(e.to_string()))?;
        certificate.log_checkpoint = Some(transparency_log.append(&checkpoint_payload).await?);

        let mut decision_state = self.decision_state.lock().await;
        if decision_state.counter != prior_counter || decision_state.trace_hash != prior_trace_hash
        {
            if let Some(slot) = slot {
                if decision_state.slot_locks.get(&slot) == Some(&payload_hash) {
                    if let Some(existing_certificate) =
                        decision_state.slot_certificates.get(&slot).cloned()
                    {
                        return Ok(Some((
                            existing_certificate.counter,
                            existing_certificate.trace_hash,
                            existing_certificate,
                        )));
                    }
                }
            }
            return Err(anyhow!(
                "guardian decision state advanced while signing consensus payload; retry"
            ));
        }

        decision_state.counter = counter;
        decision_state.trace_hash = trace_hash;
        if let Some(slot) = slot {
            decision_state.slot_locks.insert(slot, payload_hash);
            decision_state
                .slot_certificates
                .insert(slot, certificate.clone());
        }

        Ok(Some((counter, trace_hash, certificate)))
    }

    async fn issue_experimental_witness_certificate(
        &self,
        guardian_certificate: &GuardianQuorumCertificate,
        witness_manifest_hash: [u8; 32],
        reassignment_depth: u8,
        producer_account_id: AccountId,
        height: u64,
        view: u64,
        recovery_binding: Option<GuardianWitnessRecoveryBinding>,
        recovery_share_envelope: Option<&AssignedRecoveryShareEnvelopeV1>,
    ) -> Result<GuardianWitnessCertificate> {
        let witness_client = self
            .witness_committee_clients
            .get(&witness_manifest_hash)
            .ok_or_else(|| {
                anyhow!("requested witness manifest is not configured on this guardian")
            })?;
        let transparency_log_id = if witness_client
            .manifest
            .transparency_log_id
            .trim()
            .is_empty()
        {
            self.default_transparency_log_id.clone()
        } else {
            witness_client.manifest.transparency_log_id.clone()
        };
        let transparency_log = self.transparency_log_for(&transparency_log_id)?;
        let statement = GuardianWitnessStatement {
            producer_account_id,
            height,
            view,
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
            recovery_binding,
        };
        if let Some(recovery_share_envelope) = recovery_share_envelope {
            self.verify_and_store_assigned_recovery_share_envelope(
                &statement,
                witness_manifest_hash,
                recovery_share_envelope,
            )?;
        }
        let mut witness_certificate = witness_client
            .sign_witness_statement(&statement, reassignment_depth, recovery_share_envelope)
            .await?;
        let checkpoint_payload = codec::to_bytes_canonical(&(&statement, &witness_certificate))
            .map_err(|e| anyhow!(e.to_string()))?;
        witness_certificate.log_checkpoint =
            Some(transparency_log.append(&checkpoint_payload).await?);
        Ok(witness_certificate)
    }

    fn build_asymptote_observer_observation_request(
        guardian_certificate: &GuardianQuorumCertificate,
        assignment: &ioi_types::app::AsymptoteObserverAssignment,
        block_hash: [u8; 32],
    ) -> AsymptoteObserverObservationRequest {
        AsymptoteObserverObservationRequest {
            epoch: guardian_certificate.epoch,
            assignment: assignment.clone(),
            block_hash,
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
        }
    }

    fn observation_request_statement(
        request: &AsymptoteObserverObservationRequest,
    ) -> AsymptoteObserverStatement {
        AsymptoteObserverStatement {
            epoch: request.epoch,
            assignment: request.assignment.clone(),
            block_hash: request.block_hash,
            guardian_manifest_hash: request.guardian_manifest_hash,
            guardian_decision_hash: request.guardian_decision_hash,
            guardian_counter: request.guardian_counter,
            guardian_trace_hash: request.guardian_trace_hash,
            guardian_measurement_root: request.guardian_measurement_root,
            guardian_checkpoint_root: request.guardian_checkpoint_root,
            verdict: ioi_types::app::AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [0u8; 32],
        }
    }

    fn hash_guardianized_value<T: parity_scale_codec::Encode>(value: &T) -> Result<[u8; 32]> {
        digest_to_array(Sha256::digest(&value.encode()).map_err(|e| anyhow!(e.to_string()))?)
    }

    fn build_observer_challenge(
        kind: AsymptoteObserverChallengeKind,
        challenger_account_id: AccountId,
        assignment: Option<ioi_types::app::AsymptoteObserverAssignment>,
        observation_request: Option<AsymptoteObserverObservationRequest>,
        transcript: Option<AsymptoteObserverTranscript>,
        canonical_close: Option<AsymptoteObserverCanonicalClose>,
        evidence_hash: [u8; 32],
        details: impl Into<String>,
    ) -> Result<AsymptoteObserverChallenge> {
        let details = details.into();
        let mut challenge = AsymptoteObserverChallenge {
            challenge_id: [0u8; 32],
            epoch: assignment
                .as_ref()
                .map(|assignment| assignment.epoch)
                .or_else(|| observation_request.as_ref().map(|request| request.epoch))
                .unwrap_or_default(),
            height: assignment
                .as_ref()
                .map(|assignment| assignment.height)
                .or_else(|| {
                    observation_request
                        .as_ref()
                        .map(|request| request.assignment.height)
                })
                .unwrap_or_default(),
            view: assignment
                .as_ref()
                .map(|assignment| assignment.view)
                .or_else(|| {
                    observation_request
                        .as_ref()
                        .map(|request| request.assignment.view)
                })
                .unwrap_or_default(),
            kind,
            challenger_account_id,
            assignment,
            observation_request,
            transcript,
            canonical_close,
            evidence_hash,
            details,
        };
        challenge.challenge_id = Self::hash_guardianized_value(&challenge)?;
        Ok(challenge)
    }

    async fn issue_asymptote_observer_certificate(
        &self,
        statement: &AsymptoteObserverStatement,
        requested_manifest_hash: Option<[u8; 32]>,
    ) -> Result<AsymptoteObserverCertificate> {
        let Some(committee_client) = &self.committee_client else {
            return Err(anyhow!("guardian committee signing is not configured"));
        };
        if statement.assignment.observer_account_id
            != committee_client.manifest.validator_account_id
        {
            return Err(anyhow!(
                "observer statement is assigned to a different validator account"
            ));
        }
        if statement.epoch != committee_client.manifest.epoch {
            return Err(anyhow!(
                "observer statement epoch does not match local committee epoch"
            ));
        }
        let payload_hash = digest_to_array(
            Sha256::digest(
                &codec::to_bytes_canonical(statement).map_err(|e| anyhow!(e.to_string()))?,
            )
            .map_err(|e| anyhow!(e.to_string()))?,
        )?;
        if let Some(manifest_hash) = requested_manifest_hash.filter(|hash| *hash != [0u8; 32]) {
            if manifest_hash != committee_client.manifest_hash() {
                return Err(anyhow!(
                    "requested guardian manifest hash does not match local committee"
                ));
            }
        }
        let trace_hash = digest_to_array(
            Sha256::digest(
                &[
                    payload_hash.as_ref(),
                    committee_client.manifest_hash().as_ref(),
                    statement.assignment.epoch.to_be_bytes().as_ref(),
                    statement.assignment.height.to_be_bytes().as_ref(),
                    statement.assignment.view.to_be_bytes().as_ref(),
                    statement.assignment.round.to_be_bytes().as_ref(),
                ]
                .concat(),
            )
            .map_err(|e| anyhow!(e.to_string()))?,
        )?;
        let counter = u64::from_be_bytes(
            payload_hash[..8]
                .try_into()
                .map_err(|_| anyhow!("observer payload hash must be 32 bytes"))?,
        )
        .saturating_add(1);
        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::AsymptoteObserve as u8,
            subject: statement.assignment.observer_account_id.0.to_vec(),
            payload_hash,
            counter,
            trace_hash,
            measurement_root: committee_client.default_measurement_root(),
            policy_hash: committee_client.default_policy_hash(),
        };
        let transparency_log_id = if committee_client
            .manifest
            .transparency_log_id
            .trim()
            .is_empty()
        {
            self.default_transparency_log_id.clone()
        } else {
            committee_client.manifest.transparency_log_id.clone()
        };
        let transparency_log = self.transparency_log_for(&transparency_log_id)?;
        let mut guardian_certificate = committee_client.sign_decision(&decision, None).await?;
        let checkpoint_payload = codec::to_bytes_canonical(&(&decision, &guardian_certificate))
            .map_err(|e| anyhow!(e.to_string()))?;
        guardian_certificate.log_checkpoint =
            Some(transparency_log.append(&checkpoint_payload).await?);
        Ok(AsymptoteObserverCertificate {
            assignment: statement.assignment.clone(),
            verdict: statement.verdict,
            veto_kind: statement.veto_kind,
            evidence_hash: statement.evidence_hash,
            guardian_certificate,
        })
    }

    /// Issues an equal-authority asymptote observer certificate for the local validator when the
    /// deterministic observer assignment targets this guardian's registered committee.
    pub async fn observe_asymptote_statement(
        &self,
        statement: &AsymptoteObserverStatement,
        requested_manifest_hash: Option<[u8; 32]>,
    ) -> Result<AsymptoteObserverCertificate> {
        self.issue_asymptote_observer_certificate(statement, requested_manifest_hash)
            .await
    }

    /// Derives the deterministic observer result locally instead of signing a coordinator-authored
    /// verdict.
    pub async fn observe_asymptote_request(
        &self,
        request: &AsymptoteObserverObservationRequest,
        requested_manifest_hash: Option<[u8; 32]>,
    ) -> Result<AsymptoteObserverObservation> {
        let Some(committee_client) = &self.committee_client else {
            return Err(anyhow!("guardian committee signing is not configured"));
        };
        if let Some(manifest_hash) = requested_manifest_hash.filter(|hash| *hash != [0u8; 32]) {
            if manifest_hash != committee_client.manifest_hash() {
                return Err(anyhow!(
                    "requested guardian manifest hash does not match local committee"
                ));
            }
        }
        let local_account_id = committee_client.manifest.validator_account_id;
        let local_epoch = committee_client.manifest.epoch;
        if request.assignment.observer_account_id != local_account_id {
            return Err(anyhow!(
                "observation request targeted observer {} but local committee belongs to {}",
                hex::encode(request.assignment.observer_account_id),
                hex::encode(local_account_id)
            ));
        }
        if request.epoch != local_epoch || request.assignment.epoch != local_epoch {
            return Err(anyhow!(
                "observation request epoch {} does not match local committee epoch {}",
                request.epoch,
                local_epoch
            ));
        }
        if request.block_hash == [0u8; 32]
            || request.guardian_manifest_hash == [0u8; 32]
            || request.guardian_decision_hash == [0u8; 32]
            || request.guardian_trace_hash == [0u8; 32]
            || request.guardian_counter == 0
        {
            return Ok(AsymptoteObserverObservation {
                transcript: None,
                challenge: Some(Self::build_observer_challenge(
                    AsymptoteObserverChallengeKind::TranscriptMismatch,
                    local_account_id,
                    Some(request.assignment.clone()),
                    Some(request.clone()),
                    None,
                    None,
                    canonical_asymptote_observer_observation_request_hash(request)
                        .map_err(|e| anyhow!(e))?,
                    "observation request is missing canonical slot-binding fields",
                )?),
            });
        }
        let statement = Self::observation_request_statement(request);
        let observer_certificate = self
            .issue_asymptote_observer_certificate(&statement, requested_manifest_hash)
            .await?;
        Ok(AsymptoteObserverObservation {
            transcript: Some(AsymptoteObserverTranscript {
                statement,
                guardian_certificate: observer_certificate.guardian_certificate,
            }),
            challenge: None,
        })
    }

    async fn request_remote_asymptote_observer_certificate(
        &self,
        statement: &AsymptoteObserverStatement,
        manifest: &GuardianCommitteeManifest,
    ) -> Result<AsymptoteObserverCertificate> {
        let observation_request = AsymptoteObserverObservationRequest {
            epoch: statement.epoch,
            assignment: statement.assignment.clone(),
            block_hash: statement.block_hash,
            guardian_manifest_hash: statement.guardian_manifest_hash,
            guardian_decision_hash: statement.guardian_decision_hash,
            guardian_counter: statement.guardian_counter,
            guardian_trace_hash: statement.guardian_trace_hash,
            guardian_measurement_root: statement.guardian_measurement_root,
            guardian_checkpoint_root: statement.guardian_checkpoint_root,
        };
        let local_manifest_hash = self
            .committee_client
            .as_ref()
            .map(|committee| committee.manifest_hash());
        let manifest_hash =
            canonical_manifest_hash(manifest).map_err(|e| anyhow!(e.to_string()))?;
        if local_manifest_hash == Some(manifest_hash) {
            let observation = self
                .observe_asymptote_request(&observation_request, Some(manifest_hash))
                .await?;
            if observation.challenge.is_some() {
                return Err(anyhow!(
                    "observer returned a challenge while legacy sampled-close mode expected an ok certificate"
                ));
            }
            let transcript = observation
                .transcript
                .ok_or_else(|| anyhow!("observer did not return a transcript"))?;
            return Ok(AsymptoteObserverCertificate {
                assignment: transcript.statement.assignment.clone(),
                verdict: transcript.statement.verdict,
                veto_kind: transcript.statement.veto_kind,
                evidence_hash: transcript.statement.evidence_hash,
                guardian_certificate: transcript.guardian_certificate,
            });
        }

        let request = ObserveAsymptoteRequest {
            observation_request: codec::to_bytes_canonical(&observation_request)
                .map_err(|e| anyhow!(e.to_string()))?,
            manifest_hash: manifest_hash.to_vec(),
        };
        let endpoints = manifest
            .members
            .iter()
            .filter_map(|member| member.endpoint.as_ref())
            .map(|endpoint| normalize_guardian_endpoint(endpoint))
            .collect::<BTreeSet<_>>();
        if endpoints.is_empty() {
            return Err(anyhow!(
                "observer manifest for {} does not expose any guardian endpoints",
                hex::encode(manifest_hash)
            ));
        }

        let mut last_error = None;
        for endpoint in endpoints {
            let channel = {
                let mut channels = self.observer_rpc_channels.lock().await;
                channels
                    .entry(endpoint.clone())
                    .or_insert_with(|| {
                        Channel::from_shared(endpoint.clone())
                            .expect("normalized guardian endpoint should be valid")
                            .connect_lazy()
                    })
                    .clone()
            };
            let mut endpoint_error = None;
            for attempt in 0..8 {
                match async {
                    let mut client = GuardianControlClient::new(channel.clone());
                    let response = client
                        .observe_asymptote(request.clone())
                        .await?
                        .into_inner();
                    let observation: AsymptoteObserverObservation =
                        codec::from_bytes_canonical(&response.observation)
                            .map_err(|e| anyhow!(e.to_string()))?;
                    if observation.challenge.is_some() {
                        return Err(anyhow!(
                            "observer returned a challenge while legacy sampled-close mode expected an ok certificate"
                        ));
                    }
                    let transcript = observation
                        .transcript
                        .ok_or_else(|| anyhow!("observer did not return a transcript"))?;
                    Ok(AsymptoteObserverCertificate {
                        assignment: transcript.statement.assignment.clone(),
                        verdict: transcript.statement.verdict,
                        veto_kind: transcript.statement.veto_kind,
                        evidence_hash: transcript.statement.evidence_hash,
                        guardian_certificate: transcript.guardian_certificate,
                    })
                }
                .await
                {
                    Ok(observer_certificate) => return Ok(observer_certificate),
                    Err(error) => {
                        endpoint_error = Some(anyhow!("{endpoint}: {error}"));
                        if attempt < 7 {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
            last_error = endpoint_error;
        }

        Err(last_error.unwrap_or_else(|| anyhow!("observer certificate request failed")))
    }

    async fn request_remote_asymptote_observer_observation(
        &self,
        request: &AsymptoteObserverObservationRequest,
        manifest: &GuardianCommitteeManifest,
    ) -> Result<AsymptoteObserverObservation> {
        let local_manifest_hash = self
            .committee_client
            .as_ref()
            .map(|committee| committee.manifest_hash());
        let manifest_hash =
            canonical_manifest_hash(manifest).map_err(|e| anyhow!(e.to_string()))?;
        if local_manifest_hash == Some(manifest_hash) {
            return self
                .observe_asymptote_request(request, Some(manifest_hash))
                .await;
        }

        let rpc_request = ObserveAsymptoteRequest {
            observation_request: codec::to_bytes_canonical(request)
                .map_err(|e| anyhow!(e.to_string()))?,
            manifest_hash: manifest_hash.to_vec(),
        };
        let endpoints = manifest
            .members
            .iter()
            .filter_map(|member| member.endpoint.as_ref())
            .map(|endpoint| normalize_guardian_endpoint(endpoint))
            .collect::<BTreeSet<_>>();
        if endpoints.is_empty() {
            return Err(anyhow!(
                "observer manifest for {} does not expose any guardian endpoints",
                hex::encode(manifest_hash)
            ));
        }

        let mut last_error = None;
        for endpoint in endpoints {
            let channel = {
                let mut channels = self.observer_rpc_channels.lock().await;
                channels
                    .entry(endpoint.clone())
                    .or_insert_with(|| {
                        Channel::from_shared(endpoint.clone())
                            .expect("normalized guardian endpoint should be valid")
                            .connect_lazy()
                    })
                    .clone()
            };
            let mut endpoint_error = None;
            for attempt in 0..8 {
                match async {
                    let mut client = GuardianControlClient::new(channel.clone());
                    let response = client
                        .observe_asymptote(rpc_request.clone())
                        .await?
                        .into_inner();
                    codec::from_bytes_canonical(&response.observation)
                        .map_err(|e| anyhow!(e.to_string()))
                }
                .await
                {
                    Ok(observation) => return Ok(observation),
                    Err(error) => {
                        endpoint_error = Some(anyhow!("{endpoint}: {error}"));
                        if attempt < 7 {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
            last_error = endpoint_error;
        }

        Err(last_error.unwrap_or_else(|| anyhow!("observer observation request failed")))
    }

    /// Issues a stronger witness-backed proof for a consensus slot without changing the base block
    /// identity. The guardian certificate is reused from the slot lock when already present.
    pub async fn seal_consensus_with_guardian(
        &self,
        payload_hash: [u8; 32],
        height: u64,
        view: u64,
        subject: Vec<u8>,
        expected_counter: u64,
        expected_trace_hash: [u8; 32],
        requested_measurement_root: Option<[u8; 32]>,
        requested_policy_hash: Option<[u8; 32]>,
        requested_manifest_hash: Option<[u8; 32]>,
        witness_manifest_hashes: Vec<[u8; 32]>,
        witness_recovery_bindings: Vec<GuardianWitnessRecoveryBindingAssignment>,
        witness_recovery_share_envelopes: Vec<AssignedRecoveryShareEnvelopeV1>,
        observer_plan: Vec<AsymptoteObserverPlanEntry>,
        policy: AsymptotePolicy,
        witness_reassignment_depth: u8,
    ) -> Result<(
        u64,
        [u8; 32],
        GuardianQuorumCertificate,
        SealedFinalityProof,
    )> {
        if witness_manifest_hashes.is_empty() && observer_plan.is_empty() {
            return Err(anyhow!(
                "asymptote sealing requires witness manifests or equal-authority observer plans"
            ));
        }
        if !witness_manifest_hashes.is_empty() && !observer_plan.is_empty() {
            return Err(anyhow!(
                "asymptote sealing does not allow witness and observer plans in the same proof"
            ));
        }
        let producer_account_id = subject
            .as_slice()
            .try_into()
            .map(AccountId)
            .map_err(|_| anyhow!("consensus subject must be a 32-byte account id"))?;
        let committee_client = self
            .committee_client
            .as_ref()
            .ok_or_else(|| anyhow!("guardian committee signing is not configured"))?;
        let (_, _, guardian_certificate) = self
            .issue_guardian_quorum_certificate(
                GuardianDecisionDomain::ConsensusSlot,
                Some((height, view)),
                subject,
                payload_hash,
                expected_counter,
                expected_trace_hash,
                requested_measurement_root,
                requested_policy_hash,
                requested_manifest_hash,
            )
            .await?
            .ok_or_else(|| anyhow!("guardian committee signing is not configured"))?;

        let mut witness_certificates = Vec::new();
        let mut observer_certificates = Vec::new();
        let mut observer_transcripts = Vec::new();
        let mut observer_challenges = Vec::new();
        let mut observer_close_certificate = None;
        let mut observer_transcript_commitment = None;
        let mut observer_challenge_commitment = None;
        let mut observer_canonical_close = None;
        let mut observer_canonical_abort = None;
        let mut finality_tier = FinalityTier::SealedFinal;
        let mut collapse_state = CollapseState::SealedFinal;
        let witness_recovery_bindings = witness_recovery_bindings
            .into_iter()
            .map(|assignment| {
                (
                    assignment.witness_manifest_hash,
                    assignment.recovery_binding,
                )
            })
            .collect::<HashMap<_, _>>();
        let witness_recovery_share_envelopes = witness_recovery_share_envelopes
            .into_iter()
            .map(|envelope| (envelope.share_material.witness_manifest_hash, envelope))
            .collect::<HashMap<_, _>>();
        for witness_manifest_hash in witness_recovery_share_envelopes.keys() {
            if !witness_recovery_bindings.contains_key(witness_manifest_hash) {
                return Err(anyhow!(
                    "assigned recovery share envelope provided without a matching recovery binding"
                ));
            }
        }
        if !observer_plan.is_empty() {
            if policy.observer_sealing_mode == AsymptoteObserverSealingMode::CanonicalChallengeV1 {
                if policy.observer_challenge_window_ms == 0 {
                    return Err(anyhow!(
                        "canonical observer sealing requires a non-zero challenge window"
                    ));
                }
                let assignments = observer_plan
                    .iter()
                    .map(|entry| entry.assignment.clone())
                    .collect::<Vec<_>>();
                let assignments_hash = canonical_asymptote_observer_assignments_hash(&assignments)
                    .map_err(|e| anyhow!(e))?;
                let transcript_conflict =
                    |kind: AsymptoteObserverChallengeKind,
                     assignment: &ioi_types::app::AsymptoteObserverAssignment,
                     transcript: &AsymptoteObserverTranscript,
                     details: String|
                     -> Result<AsymptoteObserverChallenge> {
                        Self::build_observer_challenge(
                            kind,
                            producer_account_id,
                            Some(assignment.clone()),
                            None,
                            Some(transcript.clone()),
                            None,
                            canonical_asymptote_observer_transcript_hash(transcript)
                                .map_err(|e| anyhow!(e))?,
                            details,
                        )
                    };
                for observer in &observer_plan {
                    let observation_request = Self::build_asymptote_observer_observation_request(
                        &guardian_certificate,
                        &observer.assignment,
                        payload_hash,
                    );
                    match self
                        .request_remote_asymptote_observer_observation(
                            &observation_request,
                            &observer.manifest,
                        )
                        .await
                    {
                        Ok(observation) => {
                            let AsymptoteObserverObservation {
                                transcript,
                                challenge,
                            } = observation;
                            let mut saw_observation = false;
                            if let Some(transcript) = transcript {
                                saw_observation = true;
                                if transcript.statement.assignment != observer.assignment {
                                    observer_challenges.push(transcript_conflict(
                                        AsymptoteObserverChallengeKind::ConflictingTranscript,
                                        &observer.assignment,
                                        &transcript,
                                        format!(
                                            "observer transcript assignment mismatch for {}",
                                            hex::encode(observer.assignment.observer_account_id)
                                        ),
                                    )?);
                                } else if transcript.statement.verdict
                                    != ioi_types::app::AsymptoteObserverVerdict::Ok
                                    || transcript.statement.veto_kind.is_some()
                                {
                                    observer_challenges.push(transcript_conflict(
                                        AsymptoteObserverChallengeKind::VetoTranscriptPresent,
                                        &observer.assignment,
                                        &transcript,
                                        format!(
                                            "observer transcript returned a non-ok verdict for {}",
                                            hex::encode(observer.assignment.observer_account_id)
                                        ),
                                    )?);
                                } else {
                                    observer_transcripts.push(transcript);
                                }
                            }
                            if let Some(challenge) = challenge {
                                saw_observation = true;
                                observer_challenges.push(challenge);
                            }
                            if !saw_observation {
                                observer_challenges.push(Self::build_observer_challenge(
                                    AsymptoteObserverChallengeKind::MissingTranscript,
                                    producer_account_id,
                                    Some(observer.assignment.clone()),
                                    None,
                                    None,
                                    None,
                                    canonical_asymptote_observer_assignment_hash(
                                        &observer.assignment,
                                    )
                                    .map_err(anyhow::Error::msg)?,
                                    format!(
                                        "observer {} returned neither transcript nor challenge",
                                        hex::encode(observer.assignment.observer_account_id)
                                    ),
                                )?);
                            }
                        }
                        Err(error) => {
                            observer_challenges.push(Self::build_observer_challenge(
                                AsymptoteObserverChallengeKind::MissingTranscript,
                                producer_account_id,
                                Some(observer.assignment.clone()),
                                None,
                                None,
                                None,
                                canonical_asymptote_observer_assignment_hash(&observer.assignment)
                                    .map_err(anyhow::Error::msg)?,
                                format!(
                                    "observer {} did not publish a transcript: {error}",
                                    hex::encode(observer.assignment.observer_account_id)
                                ),
                            )?);
                        }
                    }
                }
                let transcript_count = u16::try_from(observer_transcripts.len())
                    .map_err(|_| anyhow!("observer transcript count exceeds u16"))?;
                let challenge_count = u16::try_from(observer_challenges.len())
                    .map_err(|_| anyhow!("observer challenge count exceeds u16"))?;
                let transcripts_root =
                    canonical_asymptote_observer_transcripts_hash(&observer_transcripts)
                        .map_err(|e| anyhow!(e))?;
                let challenges_root =
                    canonical_asymptote_observer_challenges_hash(&observer_challenges)
                        .map_err(|e| anyhow!(e))?;
                observer_transcript_commitment = Some(AsymptoteObserverTranscriptCommitment {
                    epoch: guardian_certificate.epoch,
                    height,
                    view,
                    assignments_hash,
                    transcripts_root,
                    transcript_count,
                });
                observer_challenge_commitment = Some(AsymptoteObserverChallengeCommitment {
                    epoch: guardian_certificate.epoch,
                    height,
                    view,
                    challenges_root,
                    challenge_count,
                });
                let challenge_cutoff_timestamp_ms: u64 = SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_millis()
                    .try_into()
                    .map_err(|_| anyhow!("challenge cutoff timestamp overflow"))?;
                if observer_challenges.is_empty()
                    && observer_transcripts.len() == observer_plan.len()
                {
                    observer_canonical_close = Some(AsymptoteObserverCanonicalClose {
                        epoch: guardian_certificate.epoch,
                        height,
                        view,
                        assignments_hash,
                        transcripts_root,
                        challenges_root,
                        transcript_count,
                        challenge_count,
                        challenge_cutoff_timestamp_ms: challenge_cutoff_timestamp_ms
                            .saturating_add(policy.observer_challenge_window_ms),
                    });
                } else {
                    finality_tier = FinalityTier::BaseFinal;
                    collapse_state = CollapseState::Abort;
                    observer_canonical_abort = Some(AsymptoteObserverCanonicalAbort {
                        epoch: guardian_certificate.epoch,
                        height,
                        view,
                        assignments_hash,
                        transcripts_root,
                        challenges_root,
                        transcript_count,
                        challenge_count,
                        challenge_cutoff_timestamp_ms: challenge_cutoff_timestamp_ms
                            .saturating_add(policy.observer_challenge_window_ms),
                    });
                }
            } else {
                observer_close_certificate = Some(AsymptoteObserverCloseCertificate {
                    epoch: guardian_certificate.epoch,
                    height,
                    view,
                    assignments_hash: canonical_asymptote_observer_assignments_hash(
                        &observer_plan
                            .iter()
                            .map(|entry| entry.assignment.clone())
                            .collect::<Vec<_>>(),
                    )
                    .map_err(|e| anyhow!(e))?,
                    expected_assignments: u16::try_from(observer_plan.len())
                        .map_err(|_| anyhow!("observer plan length exceeds u16"))?,
                    ok_count: u16::try_from(observer_plan.len())
                        .map_err(|_| anyhow!("observer plan length exceeds u16"))?,
                    veto_count: 0,
                });
                for observer in observer_plan {
                    let statement = Self::observation_request_statement(
                        &Self::build_asymptote_observer_observation_request(
                            &guardian_certificate,
                            &observer.assignment,
                            payload_hash,
                        ),
                    );
                    let observer_certificate = self
                        .request_remote_asymptote_observer_certificate(
                            &statement,
                            &observer.manifest,
                        )
                        .await?;
                    if observer_certificate.assignment != observer.assignment {
                        return Err(anyhow!(
                            "observer certificate assignment mismatch for observer {}",
                            hex::encode(observer.assignment.observer_account_id)
                        ));
                    }
                    observer_certificates.push(observer_certificate);
                }
            }
        } else {
            let mut unique_witness_manifests = Vec::new();
            let mut seen = BTreeSet::new();
            for manifest_hash in witness_manifest_hashes {
                if manifest_hash == [0u8; 32] || !seen.insert(manifest_hash) {
                    continue;
                }
                unique_witness_manifests.push(manifest_hash);
            }
            witness_certificates = Vec::with_capacity(unique_witness_manifests.len());
            for witness_manifest_hash in unique_witness_manifests {
                let recovery_binding = witness_recovery_bindings
                    .get(&witness_manifest_hash)
                    .cloned();
                let recovery_share_envelope =
                    witness_recovery_share_envelopes.get(&witness_manifest_hash);
                if recovery_binding.is_some() && recovery_share_envelope.is_none() {
                    return Err(anyhow!(
                        "assigned recovery share envelope is required before witness signing for manifest {}",
                        hex::encode(witness_manifest_hash)
                    ));
                }
                witness_certificates.push(
                    self.issue_experimental_witness_certificate(
                        &guardian_certificate,
                        witness_manifest_hash,
                        witness_reassignment_depth,
                        producer_account_id,
                        height,
                        view,
                        recovery_binding,
                        recovery_share_envelope,
                    )
                    .await?,
                );
            }
        }

        let sealed_proof = SealedFinalityProof {
            epoch: guardian_certificate.epoch,
            finality_tier,
            collapse_state,
            guardian_manifest_hash: guardian_certificate.manifest_hash,
            guardian_decision_hash: guardian_certificate.decision_hash,
            guardian_counter: guardian_certificate.counter,
            guardian_trace_hash: guardian_certificate.trace_hash,
            guardian_measurement_root: guardian_certificate.measurement_root,
            policy_hash: requested_policy_hash
                .filter(|hash| *hash != [0u8; 32])
                .unwrap_or_else(|| committee_client.default_policy_hash()),
            witness_certificates,
            observer_certificates,
            observer_close_certificate,
            observer_transcripts,
            observer_challenges,
            observer_transcript_commitment,
            observer_challenge_commitment,
            observer_canonical_close,
            observer_canonical_abort,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        };

        Ok((
            guardian_certificate.counter,
            guardian_certificate.trace_hash,
            guardian_certificate.clone(),
            sealed_proof,
        ))
    }

    /// Appends witness-fault evidence to the guardian transparency log and returns the resulting
    /// checkpoint.
    pub async fn report_witness_fault_evidence(
        &self,
        evidence: &GuardianWitnessFaultEvidence,
    ) -> Result<GuardianLogCheckpoint> {
        let payload = codec::to_bytes_canonical(evidence).map_err(|e| anyhow!(e.to_string()))?;
        self.default_transparency_log()?.append(&payload).await
    }

    /// Signs a consensus payload through the configured guardian committee and returns the legacy
    /// signature plus the emitted guardian quorum certificate.
    pub async fn sign_consensus_with_guardian(
        &self,
        signer: &libp2p::identity::Keypair,
        payload_hash: [u8; 32],
        height: u64,
        view: u64,
        subject: Vec<u8>,
        expected_counter: u64,
        expected_trace_hash: [u8; 32],
        requested_measurement_root: Option<[u8; 32]>,
        requested_policy_hash: Option<[u8; 32]>,
        requested_manifest_hash: Option<[u8; 32]>,
        requested_witness_manifest_hash: Option<[u8; 32]>,
        witness_reassignment_depth: u8,
        experimental_recovery_binding: Option<GuardianWitnessRecoveryBinding>,
    ) -> Result<SignatureBundle> {
        let producer_account_id = requested_witness_manifest_hash
            .filter(|hash| *hash != [0u8; 32])
            .map(|_| {
                subject
                    .as_slice()
                    .try_into()
                    .map(AccountId)
                    .map_err(|_| anyhow!("consensus subject must be a 32-byte account id"))
            })
            .transpose()?;
        let (counter, trace_hash, mut guardian_certificate) = self
            .issue_guardian_quorum_certificate(
                GuardianDecisionDomain::ConsensusSlot,
                Some((height, view)),
                subject.clone(),
                payload_hash,
                expected_counter,
                expected_trace_hash,
                requested_measurement_root,
                requested_policy_hash,
                requested_manifest_hash,
            )
            .await?
            .ok_or_else(|| anyhow!("guardian committee signing is not configured"))?;

        if let Some(witness_manifest_hash) =
            requested_witness_manifest_hash.filter(|hash| *hash != [0u8; 32])
        {
            guardian_certificate.experimental_witness_certificate = Some(
                self.issue_experimental_witness_certificate(
                    &guardian_certificate,
                    witness_manifest_hash,
                    witness_reassignment_depth,
                    producer_account_id
                        .ok_or_else(|| anyhow!("missing witness producer account id"))?,
                    height,
                    view,
                    experimental_recovery_binding,
                    None,
                )
                .await?,
            );
        }

        let mut signed_payload = Vec::with_capacity(32 + 8 + 32);
        signed_payload.extend_from_slice(&payload_hash);
        signed_payload.extend_from_slice(&counter.to_be_bytes());
        signed_payload.extend_from_slice(&trace_hash);

        Ok(SignatureBundle {
            signature: signer.sign(&signed_payload)?,
            counter,
            trace_hash,
            guardian_certificate: Some(guardian_certificate),
            sealed_finality_proof: None,
        })
    }

    /// Signs a canonical guardian decision with the local committee member keys hosted by this
    /// Guardian instance. Used by remote committee fan-out to gather partial BLS signatures.
    pub async fn sign_committee_decision_members(
        &self,
        decision: &GuardianDecision,
        requested_manifest_hash: Option<[u8; 32]>,
        slot: Option<(u64, u64)>,
    ) -> Result<Vec<(usize, BlsSignature)>> {
        let Some(committee_client) = &self.committee_client else {
            return Err(anyhow!("guardian committee signing is not configured"));
        };

        if let Some(manifest_hash) = requested_manifest_hash.filter(|hash| *hash != [0u8; 32]) {
            if manifest_hash != committee_client.manifest_hash() {
                return Err(anyhow!(
                    "requested guardian manifest hash does not match local committee"
                ));
            }
        }

        let mut decision_state = self.decision_state.lock().await;
        let expected_counter = decision_state.counter.saturating_add(1);
        if decision.counter != expected_counter {
            return Err(anyhow!(
                "committee decision counter mismatch: expected {}, got {}",
                expected_counter,
                decision.counter
            ));
        }

        let expected_trace_hash = digest_to_array(
            Sha256::digest(
                &[
                    decision_state.trace_hash.as_ref(),
                    decision.payload_hash.as_ref(),
                    decision.counter.to_be_bytes().as_ref(),
                    committee_client.manifest_hash().as_ref(),
                ]
                .concat(),
            )
            .map_err(|e| anyhow!(e))?,
        )?;
        if decision.trace_hash != expected_trace_hash {
            return Err(anyhow!("committee decision trace hash mismatch"));
        }
        if let Some(slot) = slot {
            if let Some(locked_payload_hash) = decision_state.slot_locks.get(&slot) {
                if locked_payload_hash != &decision.payload_hash {
                    return Err(anyhow!(
                        "guardian slot already certified for a different payload at height {} view {}",
                        slot.0,
                        slot.1
                    ));
                }
            }
        }

        let decision_hash =
            canonical_decision_hash(decision).map_err(|e| anyhow!(e.to_string()))?;
        let member_signatures = committee_client
            .signer_keys
            .iter()
            .map(|(member_index, signing_key)| {
                signing_key
                    .sign(&decision_hash)
                    .map(|signature| (*member_index, signature))
                    .map_err(|e| anyhow!(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;

        decision_state.counter = decision.counter;
        decision_state.trace_hash = decision.trace_hash;
        if let Some(slot) = slot {
            decision_state
                .slot_locks
                .insert(slot, decision.payload_hash);
        }

        Ok(member_signatures)
    }

    /// Signs a witness statement with the local witness committee member keys hosted by this
    /// Guardian instance. Used by remote witness fan-out to gather partial BLS signatures.
    pub async fn sign_witness_statement_members(
        &self,
        statement: &GuardianWitnessStatement,
        requested_manifest_hash: Option<[u8; 32]>,
        recovery_share_envelope: Option<&AssignedRecoveryShareEnvelopeV1>,
    ) -> Result<Vec<(usize, BlsSignature)>> {
        let manifest_hash = requested_manifest_hash
            .filter(|hash| *hash != [0u8; 32])
            .ok_or_else(|| anyhow!("witness manifest hash is required"))?;
        let witness_client = self
            .witness_committee_clients
            .get(&manifest_hash)
            .ok_or_else(|| anyhow!("requested witness manifest is not configured"))?;
        if let Some(recovery_share_envelope) = recovery_share_envelope {
            self.verify_and_store_assigned_recovery_share_envelope(
                statement,
                manifest_hash,
                recovery_share_envelope,
            )?;
        }
        let statement_hash =
            canonical_witness_statement_hash(statement).map_err(|e| anyhow!(e.to_string()))?;
        witness_client
            .signer_keys
            .iter()
            .map(|(member_index, signing_key)| {
                signing_key
                    .sign(&statement_hash)
                    .map(|signature| (*member_index, signature))
                    .map_err(|e| anyhow!(e.to_string()))
            })
            .collect()
    }

    /// Attests to the integrity of an agentic model file by computing its hash.
    pub async fn attest_weights(&self, model_path: &str) -> Result<Vec<u8>, String> {
        let model_bytes = std::fs::read(model_path)
            .map_err(|e| format!("Failed to read agentic model file: {}", e))?;
        // FIX: Remove explicit type annotation to allow compiler inference
        let local_hash_array = Sha256::digest(&model_bytes).map_err(|e| e.to_string())?;
        log::info!(
            "[Guardian] Computed local model hash: {}",
            hex::encode(&local_hash_array)
        );
        Ok(local_hash_array.to_vec())
    }

    /// Measures a model file and issues an attestation.
    /// This is called before the Workload is allowed to load the model into VRAM.
    pub async fn attest_model_snapshot(
        &self,
        keypair: &libp2p::identity::Keypair,
        model_path: &Path,
    ) -> Result<ModelAttestation> {
        log::info!("[Guardian] Attesting model snapshot at {:?}", model_path);

        if !model_path.exists() {
            return Err(anyhow!("Model file not found: {:?}", model_path));
        }

        // Compute SHA-256 of the model file
        // For large models (GBs), we stream read.
        let mut file = File::open(model_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher
                .update(&buffer[..count])
                .map_err(|e| anyhow!(e.to_string()))?;
        }

        let hash_digest = hasher.finalize().map_err(|e| anyhow!(e.to_string()))?;
        let mut model_hash = [0u8; 32];
        // [FIX] Unwrap the result of finalize() before using as_ref() and handle error with ?
        model_hash.copy_from_slice(hash_digest.as_ref());

        // Construct attestation
        let pk_bytes = keypair.public().encode_protobuf();
        // [FIX] Use SignatureSuite::ED25519
        let account_hash = account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
            .map_err(|e| anyhow!(e))?;

        let mut attestation = ModelAttestation {
            validator_id: AccountId(account_hash),
            model_hash,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: Vec::new(),
        };

        // Sign the deterministic tuple (validator_id, model_hash, timestamp)
        // Note: Real impl would use a dedicated serialization for signing
        let sign_payload = bincode::serialize(&(
            &attestation.validator_id,
            &attestation.model_hash,
            &attestation.timestamp,
        ))?;
        attestation.signature = keypair.sign(&sign_payload)?;

        log::info!(
            "[Guardian] Generated attestation for model hash: {}",
            hex::encode(model_hash)
        );
        Ok(attestation)
    }

    /// Generates a signed `BootAttestation` by hashing the local binaries.
    ///
    /// # Arguments
    /// * `keypair`: The identity keypair used to sign the attestation.
    /// * `config`: The Guardian configuration (used to resolve binary paths).
    pub fn generate_boot_attestation(
        &self,
        keypair: &libp2p::identity::Keypair,
        config: &GuardianConfig,
    ) -> Result<BootAttestation> {
        // Resolve binary directory
        let bin_dir = if let Some(dir) = &config.binary_dir_override {
            Path::new(dir).to_path_buf()
        } else {
            std::env::current_exe()?
                .parent()
                .ok_or(anyhow!("Cannot determine binary directory"))?
                .to_path_buf()
        };

        let measure = |name: &str| -> Result<BinaryMeasurement> {
            let path = bin_dir.join(name);
            if !path.exists() {
                return Err(anyhow!("Binary not found: {:?}", path));
            }
            let bytes = std::fs::read(&path)?;
            let hash = Sha256::digest(&bytes).map_err(|e| anyhow!(e))?;
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&hash);

            Ok(BinaryMeasurement {
                name: name.to_string(),
                sha256,
                size: bytes.len() as u64,
            })
        };

        let guardian_meas = measure("guardian")?;
        let orch_meas = measure("orchestration")?;
        let workload_meas = measure("workload")?;

        let pk_bytes = keypair.public().encode_protobuf();
        // Assuming Ed25519 for the identity key
        // [FIX] Use SignatureSuite::ED25519
        let account_hash = account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
            .map_err(|e| anyhow!(e))?;

        let mut attestation = BootAttestation {
            validator_account_id: AccountId(account_hash),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            guardian: guardian_meas,
            orchestration: orch_meas,
            workload: workload_meas,
            build_metadata: env!("CARGO_PKG_VERSION").to_string(), // Or inject git hash via env
            signature: Vec::new(),
        };

        // Sign it
        let sign_bytes = attestation.to_sign_bytes()?;
        let signature = keypair.sign(&sign_bytes)?;
        attestation.signature = signature;

        log::info!(
            "[Guardian] Generated BootAttestation for validator {}. Guardian Hash: {}",
            hex::encode(account_hash),
            hex::encode(attestation.guardian.sha256)
        );

        Ok(attestation)
    }

    /// Locates, hashes, and locks sibling binaries relative to the current executable.
    pub fn verify_binaries(&self, config: &GuardianConfig) -> Result<Option<BinaryGuard>> {
        // If explicit opt-out, warn loudly.
        if !config.enforce_binary_integrity {
            tracing::warn!(
                "SECURITY WARNING: Binary integrity enforcement is DISABLED. \
                This node is vulnerable to runtime binary swapping attacks."
            );
            return Ok(None);
        }

        // Use override if present, otherwise resolve relative to current executable.
        let bin_dir = if let Some(dir) = &config.binary_dir_override {
            Path::new(dir).to_path_buf()
        } else {
            let my_path = std::env::current_exe()?;
            my_path
                .parent()
                .ok_or(anyhow!("Cannot determine binary directory"))?
                .to_path_buf()
        };

        let orch_path = bin_dir.join("orchestration");
        let work_path = bin_dir.join("workload");

        // If enabled (default), hashes MUST be present.
        let orch_hash = config.approved_orchestrator_hash.as_deref().ok_or_else(|| {
            anyhow!("Guardian failed to start: `enforce_binary_integrity` is true, but `approved_orchestrator_hash` is missing in guardian.toml")
        })?;

        let work_hash = config.approved_workload_hash.as_deref().ok_or_else(|| {
            anyhow!("Guardian failed to start: `enforce_binary_integrity` is true, but `approved_workload_hash` is missing in guardian.toml")
        })?;

        let orch_handle = self.check_binary(&orch_path, Some(orch_hash), "Orchestrator")?;
        let work_handle = self.check_binary(&work_path, Some(work_hash), "Workload")?;

        log::info!("[Guardian] Binary integrity verified. Executables locked.");

        Ok(Some(BinaryGuard {
            _handles: vec![orch_handle, work_handle],
        }))
    }

    fn check_binary(&self, path: &Path, expected_hash: Option<&str>, label: &str) -> Result<File> {
        let expected = expected_hash.ok_or_else(|| {
            anyhow!(
                "Integrity enforcement enabled but no hash provided for {}",
                label
            )
        })?;

        log::info!("[Guardian] Verifying {} at {:?}", label, path);

        // Open file for reading (this handle ensures the file exists and locks it if OS supports)
        let mut file =
            File::open(path).map_err(|e| anyhow!("Failed to open {} binary: {}", label, e))?;

        // Read entire binary into memory for hashing
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Compute SHA-256 using dcrypt
        let digest = Sha256::digest(&buffer).map_err(|e| anyhow!("Hashing failed: {}", e))?;
        let hex_digest = hex::encode(digest);

        if hex_digest != expected {
            return Err(anyhow!(
                "SECURITY VIOLATION: {} binary hash mismatch!\nExpected: {}\nComputed: {}",
                label,
                expected,
                hex_digest
            ));
        }

        // Return the open file handle to keep a lock reference (OS dependent)
        Ok(file)
    }

    /// Resolves the secure passphrase from environment or interactive prompt.
    fn resolve_passphrase(confirm: bool) -> Result<String> {
        if let Ok(p) = std::env::var("IOI_GUARDIAN_KEY_PASS") {
            return Ok(p);
        }

        if atty::is(atty::Stream::Stdin) {
            eprint!("Enter Guardian Key Passphrase: ");
            std::io::stderr().flush()?;
            let pass = rpassword::read_password()?;

            if confirm {
                eprint!("Confirm Passphrase: ");
                std::io::stderr().flush()?;
                let conf = rpassword::read_password()?;
                if pass != conf {
                    return Err(anyhow!("Passphrases do not match"));
                }
            }

            if pass.is_empty() {
                return Err(anyhow!("Empty passphrase not allowed"));
            }
            Ok(pass)
        } else {
            Err(anyhow!(
                "No TTY and IOI_GUARDIAN_KEY_PASS not set. Cannot decrypt key."
            ))
        }
    }

    /// Loads an encrypted key file from disk, decrypts it, and returns the raw bytes.
    /// Rejects raw 32-byte keys (legacy seeds) to enforce encryption-at-rest.
    pub fn load_encrypted_file(path: &Path) -> Result<Vec<u8>> {
        let content = std::fs::read(path)?;

        // Check for Magic Header defined in ioi_crypto::key_store
        if content.starts_with(b"IOI-GKEY") {
            let pass = Self::resolve_passphrase(false)?;
            let secret = decrypt_key(&content, &pass)?;
            // secret is SensitiveBytes(Vec<u8>), needs explicit clone to move out
            Ok(secret.0.clone())
        } else {
            // Safety check for legacy/raw keys.
            if content.len() == 32 {
                return Err(anyhow!(
                    "SECURITY ERROR: Found unsafe raw key at {:?}. \
                    The IOI Kernel requires all validator keys to be encrypted. \
                    Please delete this file to generate a new secure key, or migrate it manually.",
                    path
                ));
            }
            // Support previous magic if transitioning
            if content.starts_with(b"IOI_ENC_V1") {
                let _pass = Self::resolve_passphrase(false)?;
                // Using the updated decrypt_key might fail if logic changed strictly.
                // We assume complete migration or compatible logic.
                // But updated decrypt_key checks for IOI-GKEY.
                return Err(anyhow!(
                    "Legacy encrypted key found. Please migrate to V1 format."
                ));
            }

            Err(anyhow!(
                "Unknown key file format or unencrypted file. Encryption is mandatory."
            ))
        }
    }

    /// Encrypts the provided data with a passphrase and saves it to disk using Atomic Write.
    /// 1. Writes to temp file.
    /// 2. Fsyncs.
    /// 3. Renames to final path.
    pub fn save_encrypted_file(path: &Path, data: &[u8]) -> Result<()> {
        println!("--- Encrypting New Secure Key ---");
        let pass = Self::resolve_passphrase(true)?;
        let encrypted = encrypt_key(data, &pass)?;

        // Atomic write pattern: Write to .tmp, sync, rename
        let mut temp_path = path.to_path_buf();
        if let Some(ext) = path.extension() {
            let mut ext_str = ext.to_os_string();
            ext_str.push(".tmp");
            temp_path.set_extension(ext_str);
        } else {
            temp_path.set_extension("tmp");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
        }

        std::fs::rename(temp_path, path)?;

        Ok(())
    }

    /// Executes a secure HTTP call on behalf of a workload.
    pub async fn secure_http_call(
        &self,
        target_domain: &str,
        path: &str,
        method: &str,
        body: Vec<u8>,
        secret_id: &str,
        signer: &libp2p::identity::Keypair,
        json_patch_path: Option<&str>, // [NEW] Added parameter
        required_finality_tier: FinalityTier,
        sealed_finality_proof: Option<SealedFinalityProof>,
        canonical_collapse_object: Option<CanonicalCollapseObject>,
        seal_object: Option<SealObject>,
    ) -> Result<(Vec<u8>, [u8; 32], Vec<u8>, EgressReceipt)> {
        if matches!(required_finality_tier, FinalityTier::BaseFinal)
            && (seal_object.is_some() || canonical_collapse_object.is_some())
        {
            return Err(anyhow!(
                "proof-carrying seal objects and canonical collapse objects may only be supplied for SealedFinal egress"
            ));
        }
        if matches!(required_finality_tier, FinalityTier::SealedFinal)
            && (sealed_finality_proof.is_none() || canonical_collapse_object.is_none())
        {
            return Err(anyhow!(
                "sealed finality was requested for secure egress but the sealed proof or canonical collapse object was missing"
            ));
        }
        if let Some(proof) = sealed_finality_proof.as_ref() {
            if !matches!(proof.finality_tier, FinalityTier::SealedFinal)
                || !matches!(
                    proof.collapse_state,
                    ioi_types::app::CollapseState::SealedFinal
                )
            {
                return Err(anyhow!(
                    "sealed finality proof is not in the SealedFinal collapse state"
                ));
            }
        }

        // 1. Resolve the secret through the configured authority.
        let key_path = self.config_dir.join(format!("{}.key", secret_id));
        let pass = if matches!(self.production_mode, GuardianProductionMode::Development) {
            Some(Self::resolve_passphrase(false)?)
        } else {
            std::env::var("IOI_GUARDIAN_KEY_PASS").ok()
        };
        let secret_value = self
            .key_authority
            .resolve_secret_string(&key_path, pass.as_deref())
            .await?;

        // 2. Prepare the canonical request hash before secrets are injected.
        let request_hash = compute_secure_egress_request_hash(method, target_domain, path, &body)?;
        let policy_hash = digest_to_array(
            Sha256::digest(
                format!("{}|{}", secret_id, json_patch_path.unwrap_or("header")).as_bytes(),
            )
            .map_err(|e| anyhow!(e))?,
        )?;
        let seal_object = match (
            required_finality_tier,
            seal_object,
            sealed_finality_proof.as_ref(),
            canonical_collapse_object.as_ref(),
        ) {
            (FinalityTier::SealedFinal, Some(seal_object), Some(proof), Some(collapse)) => {
                verify_seal_object(&seal_object).map_err(|e| anyhow!(e))?;
                if seal_object.intent.request_hash != request_hash {
                    return Err(anyhow!(
                        "sealed effect intent request hash does not match the canonical request"
                    ));
                }
                if seal_object.intent.target != target_domain
                    || seal_object.intent.action != method
                    || seal_object.intent.path != path
                {
                    return Err(anyhow!(
                        "sealed effect intent target/action/path do not match the requested egress"
                    ));
                }
                if seal_object.intent.policy_hash != policy_hash {
                    return Err(anyhow!(
                        "sealed effect policy hash does not match the requested egress policy"
                    ));
                }
                let observer_binding =
                    sealed_finality_proof_observer_binding(proof).map_err(|e| anyhow!(e))?;
                if seal_object.epoch != proof.epoch
                    || seal_object.intent.guardian_manifest_hash != proof.guardian_manifest_hash
                    || seal_object.intent.guardian_decision_hash != proof.guardian_decision_hash
                    || seal_object.public_inputs.guardian_counter != proof.guardian_counter
                    || seal_object.public_inputs.guardian_trace_hash != proof.guardian_trace_hash
                    || seal_object.public_inputs.guardian_measurement_root
                        != proof.guardian_measurement_root
                    || seal_object.public_inputs.observer_transcripts_root
                        != observer_binding.transcripts_root
                    || seal_object.public_inputs.observer_challenges_root
                        != observer_binding.challenges_root
                    || seal_object.public_inputs.observer_resolution_hash
                        != observer_binding.resolution_hash
                {
                    return Err(anyhow!(
                        "sealed effect seal object does not match the supplied sealed finality proof"
                    ));
                }
                let expected_collapse_hash =
                    canonical_collapse_hash_for_sealed_effect(collapse, proof)
                        .map_err(|e| anyhow!(e))?;
                if seal_object.public_inputs.canonical_collapse_hash != expected_collapse_hash {
                    return Err(anyhow!(
                        "sealed effect seal object does not match the supplied canonical collapse object"
                    ));
                }
                Some(seal_object)
            }
            (FinalityTier::SealedFinal, None, Some(proof), Some(collapse)) => Some(
                build_http_egress_seal_object(
                    request_hash,
                    target_domain,
                    method,
                    path,
                    policy_hash,
                    proof,
                    collapse,
                )
                .map_err(|e| anyhow!(e))?,
            ),
            (FinalityTier::SealedFinal, _, _, _) => {
                return Err(anyhow!(
                    "sealed final egress requires both a sealed finality proof and canonical collapse object"
                ));
            }
            _ => None,
        };
        let mut extra_headers = Vec::new();

        // 3. Inject Secret (Header vs. Body)
        let final_body = if let Some(patch_path) = json_patch_path {
            // Body Injection (UCP)
            let mut json_body: Value = serde_json::from_slice(&body)
                .map_err(|e| anyhow!("Failed to parse body for injection: {}", e))?;

            // Simple recursive patch helper
            fn patch_json(value: &mut Value, path_parts: &[&str], secret: &str) -> Result<()> {
                if path_parts.is_empty() {
                    if value.is_string() {
                        // Replace template with secret
                        *value = Value::String(secret.to_string());
                        return Ok(());
                    }
                    return Err(anyhow!("Target field is not a string"));
                }

                let (head, tail) = path_parts.split_first().unwrap();

                // Handle array indexing (e.g., "handlers[0]")
                if head.ends_with(']') {
                    if let Some(open_idx) = head.find('[') {
                        let field_name = &head[..open_idx];
                        let idx_str = &head[open_idx + 1..head.len() - 1];
                        let idx: usize = idx_str.parse()?;

                        let array_field = value
                            .get_mut(field_name)
                            .ok_or(anyhow!("Field {} not found", field_name))?;

                        let item = array_field
                            .get_mut(idx)
                            .ok_or(anyhow!("Index {} out of bounds", idx))?;

                        return patch_json(item, tail, secret);
                    }
                }

                let next_val = value
                    .get_mut(*head)
                    .ok_or(anyhow!("Field {} not found", head))?;
                patch_json(next_val, tail, secret)
            }

            // Split path "payment.handlers[0].token" -> handling array syntax needs parsing
            // For MVP, assume simple dot notation or custom parser.
            // Simplified: "payment.handlers.0.token"
            let parts: Vec<&str> = patch_path.split('.').collect();
            patch_json(&mut json_body, &parts, &secret_value)?;

            serde_json::to_vec(&json_body)?
        } else {
            // Header Injection (Standard API)
            extra_headers.push(("authorization", format!("Bearer {}", secret_value)));
            body
        };

        // 4. Execute Request
        let (
            response_bytes,
            server_name,
            cert_hash,
            leaf_cert_hash,
            handshake_transcript_hash,
            request_transcript_hash,
            response_transcript_hash,
        ) = notarized_https_request(
            target_domain,
            path,
            method,
            final_body,
            extra_headers,
            &self.verifier_policy,
        )
        .await?;
        let response_hash =
            digest_to_array(Sha256::digest(&response_bytes).map_err(|e| anyhow!(e))?)?;
        let transcript_root = compute_secure_egress_transcript_root(
            request_hash,
            handshake_transcript_hash,
            request_transcript_hash,
            response_transcript_hash,
            cert_hash,
            response_hash,
        )?;

        let guardian_certificate = self
            .issue_guardian_quorum_certificate(
                GuardianDecisionDomain::SecureEgress,
                None,
                target_domain.as_bytes().to_vec(),
                transcript_root,
                0,
                [0u8; 32],
                None,
                Some(policy_hash),
                None,
            )
            .await?
            .map(|(_, _, certificate)| certificate);

        // 6. Sign the receipt-compatible attestation.
        let signature =
            self.sign_egress_attestation(signer, target_domain, &cert_hash, &response_bytes)?;
        let checkpoint = self.default_transparency_log()?.append(&signature).await?;
        if let Some(sealed_effect) = seal_object.as_ref() {
            let mut nullifiers = self.sealed_effect_nullifiers.lock().await;
            if !nullifiers.insert(sealed_effect.public_inputs.nullifier) {
                return Err(anyhow!(
                    "sealed effect nullifier has already been consumed for a prior egress"
                ));
            }
        }
        let receipt = EgressReceipt {
            request_hash,
            server_name,
            transcript_version: self.verifier_policy.tls_transcript_version,
            transcript_root,
            handshake_transcript_hash,
            request_transcript_hash,
            response_transcript_hash,
            peer_certificate_chain_hash: cert_hash,
            peer_leaf_certificate_hash: leaf_cert_hash,
            response_hash,
            policy_hash,
            finality_tier: required_finality_tier,
            guardian_certificate,
            sealed_finality_proof,
            seal_object,
            canonical_collapse_object,
            log_checkpoint: Some(checkpoint),
        };

        Ok((response_bytes, cert_hash, signature, receipt))
    }

    fn sign_egress_attestation(
        &self,
        signer: &libp2p::identity::Keypair,
        domain: &str,
        cert: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        payload.extend_from_slice(domain.as_bytes());
        payload.extend_from_slice(cert);
        let body_hash = Sha256::digest(body).map_err(|e| anyhow!(e))?;
        payload.extend_from_slice(&body_hash);

        let signature = signer.sign(&payload)?;
        Ok(signature)
    }
}
