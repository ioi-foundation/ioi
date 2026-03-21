// --- Signing Abstraction for Oracle-Anchored Consensus ---

/// Abstract interface for a signing authority.
/// This allows the Orchestrator to use either a local key (for development)
/// or a remote, cryptographically isolated Oracle (for production non-equivocation enforcement).
#[async_trait]
pub trait GuardianSigner: Send + Sync {
    /// Signs a consensus payload (usually a block header hash).
    /// Returns the signature along with the Oracle's counter and trace.
    async fn sign_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        height: u64,
        view: u64,
        experimental_witness_manifest: Option<([u8; 32], u8)>,
        experimental_recovery_binding: Option<GuardianWitnessRecoveryBinding>,
    ) -> Result<SignatureBundle>;

    /// Requests stronger witness-backed sealed finality for an already certified slot.
    async fn seal_consensus_payload(
        &self,
        _payload_hash: [u8; 32],
        _height: u64,
        _view: u64,
        _witness_manifest_hashes: Vec<[u8; 32]>,
        _witness_recovery_bindings: Vec<GuardianWitnessRecoveryBindingAssignment>,
        _witness_recovery_share_envelopes: Vec<AssignedRecoveryShareEnvelopeV1>,
        _observer_plan: Vec<AsymptoteObserverPlanEntry>,
        _policy: AsymptotePolicy,
    ) -> Result<SealedFinalityProof> {
        Err(anyhow!("sealed finality is not supported by this signer"))
    }

    /// Loads a previously stored assigned recovery share so it can be revealed on the cold path.
    async fn load_assigned_recovery_share_material(
        &self,
        _height: u64,
        _witness_manifest_hash: [u8; 32],
        _recovery_binding: GuardianWitnessRecoveryBinding,
    ) -> Result<Option<RecoveryShareMaterial>> {
        Ok(None)
    }

    /// Persists experimental witness-fault evidence when the runtime detects witness omission or
    /// reassignment conditions.
    async fn report_witness_fault(&self, _evidence: &GuardianWitnessFaultEvidence) -> Result<()> {
        Ok(())
    }

    /// Returns the public key bytes of the signer.
    fn public_key(&self) -> Vec<u8>;
}

/// Local implementation for development/testing.
/// Mimics the Oracle's interface but uses an in-memory keypair and zeroed metadata.
pub struct LocalSigner {
    /// [FIX] Made public to allow direct access by ProviderController for non-consensus signing.
    pub keypair: ioi_crypto::sign::eddsa::Ed25519KeyPair,
    // [FIX] Added monotonic counter to satisfy Aft deterministic invariants in tests
    counter: std::sync::atomic::AtomicU64,
}

impl LocalSigner {
    /// Creates a new `LocalSigner` with the given keypair.
    pub fn new(keypair: ioi_crypto::sign::eddsa::Ed25519KeyPair) -> Self {
        Self {
            keypair,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl GuardianSigner for LocalSigner {
    async fn sign_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        _height: u64,
        _view: u64,
        _experimental_witness_manifest: Option<([u8; 32], u8)>,
        _experimental_recovery_binding: Option<GuardianWitnessRecoveryBinding>,
    ) -> Result<SignatureBundle> {
        // [FIX] Increment counter to simulate Oracle monotonicity
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;

        // To support Oracle-anchored logic even in dev mode, we must construct the same payload structure:
        // Payload_Hash || Counter || Trace (0)
        // This ensures verification logic in the consensus engine remains consistent.
        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&payload_hash);
        sig_input.extend_from_slice(&counter.to_be_bytes());
        sig_input.extend_from_slice(&[0u8; 32]); // Trace = 0

        let signature = self.keypair.private_key().sign(&sig_input)?.to_bytes();

        Ok(SignatureBundle {
            signature,
            counter,
            trace_hash: [0u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
        })
    }

    fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key().to_bytes()
    }
}

/// Remote implementation connecting to the `ioi-signer` Oracle.
pub struct RemoteSigner {
    url: String,
    client: reqwest::Client,
    // Cache public key on startup to avoid async overhead in tight loops
    public_key: Vec<u8>,
}

impl RemoteSigner {
    /// Creates a new `RemoteSigner` that connects to the specified Oracle URL
    /// and uses the provided public key for validation.
    pub fn new(url: String, public_key: Vec<u8>) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
            public_key,
        }
    }
}

#[async_trait]
impl GuardianSigner for RemoteSigner {
    async fn sign_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        _height: u64,
        _view: u64,
        _experimental_witness_manifest: Option<([u8; 32], u8)>,
        _experimental_recovery_binding: Option<GuardianWitnessRecoveryBinding>,
    ) -> Result<SignatureBundle> {
        // The Oracle expects the hash as a hex string.
        let resp = self
            .client
            .post(format!("{}/sign", self.url))
            .json(&serde_json::json!({
                "payload_hash": hex::encode(payload_hash)
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        // Parse response: { signature: "hex", counter: 123, trace_hash: "hex" }
        let sig_hex = resp["signature"]
            .as_str()
            .ok_or(anyhow!("Missing signature in Oracle response"))?;
        let counter = resp["counter"]
            .as_u64()
            .ok_or(anyhow!("Missing counter in Oracle response"))?;
        let trace_hex = resp["trace_hash"]
            .as_str()
            .ok_or(anyhow!("Missing trace_hash in Oracle response"))?;

        let signature = hex::decode(sig_hex)?;
        let trace_hash_vec = hex::decode(trace_hex)?;
        let trace_hash: [u8; 32] = trace_hash_vec
            .try_into()
            .map_err(|_| anyhow!("Invalid trace hash length"))?;

        Ok(SignatureBundle {
            signature,
            counter,
            trace_hash,
            guardian_certificate: None,
            sealed_finality_proof: None,
        })
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[derive(Debug, Clone, Default)]
struct GuardianDecisionState {
    counter: u64,
    trace_hash: [u8; 32],
    slot_locks: HashMap<(u64, u64), [u8; 32]>,
    slot_certificates: HashMap<(u64, u64), GuardianQuorumCertificate>,
}

#[derive(Clone)]
struct GuardianCommitteeClient {
    manifest: GuardianCommitteeManifest,
    manifest_hash: [u8; 32],
    signer_keys: Vec<(usize, BlsPrivateKey)>,
    remote_members: Vec<RemoteCommitteeMember>,
}

#[derive(Debug, Clone)]
struct RemoteCommitteeMember {
    endpoint: String,
    channel: Channel,
}

#[derive(Clone)]
struct GuardianWitnessCommitteeClient {
    manifest: GuardianWitnessCommitteeManifest,
    manifest_hash: [u8; 32],
    signer_keys: Vec<(usize, BlsPrivateKey)>,
    remote_members: Vec<RemoteCommitteeMember>,
}

impl GuardianCommitteeClient {
    fn remote_rpc_timeout() -> Duration {
        std::env::var("IOI_GUARDIAN_REMOTE_RPC_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_millis(750))
    }

    fn from_config(
        config: &GuardianConfig,
        validator_account_id: AccountId,
    ) -> Result<Option<Self>> {
        if config.committee.members.is_empty() {
            return Ok(None);
        }
        if config.committee.threshold == 0 {
            return Err(anyhow!("guardian committee threshold must be at least 1"));
        }
        if usize::from(config.committee.threshold) > config.committee.members.len() {
            return Err(anyhow!(
                "guardian committee threshold {} exceeds member count {}",
                config.committee.threshold,
                config.committee.members.len()
            ));
        }
        if usize::from(config.committee.threshold) <= config.committee.members.len() / 2 {
            return Err(anyhow!(
                "guardian committee threshold {} must be a strict majority for size {}",
                config.committee.threshold,
                config.committee.members.len()
            ));
        }
        if matches!(config.production_mode, GuardianProductionMode::Production) {
            if config.committee.members.len() % 2 != 0 {
                return Err(anyhow!(
                    "production guardian committees must be even-sized; got {} members",
                    config.committee.members.len()
                ));
            }
            let providers = config
                .committee
                .members
                .iter()
                .filter_map(|member| member.provider.clone())
                .collect::<BTreeSet<_>>();
            let regions = config
                .committee
                .members
                .iter()
                .filter_map(|member| member.region.clone())
                .collect::<BTreeSet<_>>();
            let host_classes = config
                .committee
                .members
                .iter()
                .filter_map(|member| member.host_class.clone())
                .collect::<BTreeSet<_>>();
            let authorities = config
                .committee
                .members
                .iter()
                .filter_map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}")))
                .collect::<BTreeSet<_>>();
            if providers.len() < 2
                || regions.len() < 2
                || host_classes.len() < 2
                || authorities.len() < 2
            {
                return Err(anyhow!(
                    "production guardian committees require at least two distinct providers, regions, host classes, and key authorities"
                ));
            }
        }

        let policy_hash = digest_to_array(
            Sha256::digest(&serde_json::to_vec(&(
                config.production_mode,
                &config.hardening,
                &config.verifier_policy,
                &config.transparency_log,
            ))?)
            .map_err(|e| anyhow!(e))?,
        )?;
        let measurement_profile_root = digest_to_array(
            Sha256::digest(&serde_json::to_vec(&(
                config.approved_orchestrator_hash.clone(),
                config.approved_workload_hash.clone(),
                config.hardening.measured_boot_required,
            ))?)
            .map_err(|e| anyhow!(e))?,
        )?;

        let manifest = GuardianCommitteeManifest {
            validator_account_id,
            epoch: 1,
            threshold: config.committee.threshold,
            members: config
                .committee
                .members
                .iter()
                .map(|member| GuardianCommitteeMember {
                    member_id: member.member_id.clone(),
                    signature_suite: SignatureSuite::BLS12_381,
                    public_key: member.public_key.clone(),
                    endpoint: member.endpoint.clone(),
                    provider: member.provider.clone(),
                    region: member.region.clone(),
                    host_class: member.host_class.clone(),
                    key_authority_kind: member.key_authority_kind,
                })
                .collect(),
            measurement_profile_root,
            policy_hash,
            transparency_log_id: config.committee.transparency_log_id.clone(),
        };

        let mut signer_keys = Vec::new();
        let mut remote_members = Vec::new();
        for (index, member) in config.committee.members.iter().enumerate() {
            if let Some(path) = &member.private_key_path {
                let signing_key = load_bls_private_key(Path::new(path))?;
                signer_keys.push((index, signing_key));
            } else if let Some(endpoint) = &member.endpoint {
                let endpoint = normalize_guardian_endpoint(endpoint);
                remote_members.push(RemoteCommitteeMember {
                    channel: Channel::from_shared(endpoint.clone())?.connect_lazy(),
                    endpoint,
                });
            }
        }

        if signer_keys.len() + remote_members.len() < usize::from(manifest.threshold) {
            return Err(anyhow!(
                "guardian committee has {} reachable local/remote members but threshold is {}",
                signer_keys.len() + remote_members.len(),
                manifest.threshold
            ));
        }

        Ok(Some(Self {
            manifest_hash: canonical_manifest_hash(&manifest)
                .map_err(|e| anyhow!(e.to_string()))?,
            manifest,
            signer_keys,
            remote_members,
        }))
    }

    fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }

    fn default_measurement_root(&self) -> [u8; 32] {
        self.manifest.measurement_profile_root
    }

    fn default_policy_hash(&self) -> [u8; 32] {
        self.manifest.policy_hash
    }

    fn default_subject(&self) -> Vec<u8> {
        self.manifest.validator_account_id.0.to_vec()
    }

    async fn sign_decision(
        &self,
        decision: &GuardianDecision,
        slot: Option<(u64, u64)>,
    ) -> Result<GuardianQuorumCertificate> {
        let decision_hash =
            canonical_decision_hash(decision).map_err(|e| anyhow!(e.to_string()))?;
        let mut member_signatures = BTreeMap::<usize, BlsSignature>::new();

        for (member_index, signing_key) in &self.signer_keys {
            let signature = signing_key
                .sign(&decision_hash)
                .map_err(|e| anyhow!(e.to_string()))?;
            member_signatures.insert(*member_index, signature);
        }

        let threshold = usize::from(self.manifest.threshold);
        if member_signatures.len() < threshold {
            let remote_signatures = self
                .collect_remote_signatures(
                    decision,
                    decision_hash,
                    slot,
                    threshold.saturating_sub(member_signatures.len()),
                )
                .await?;
            for (member_index, signature) in remote_signatures {
                member_signatures.entry(member_index).or_insert(signature);
                if member_signatures.len() >= threshold {
                    break;
                }
            }
        }

        if member_signatures.len() < threshold {
            return Err(anyhow!(
                "guardian committee collected {} signatures but threshold is {}",
                member_signatures.len(),
                self.manifest.threshold
            ));
        }

        let member_signatures = member_signatures.into_iter().collect::<Vec<_>>();
        let (signers_bitfield, aggregated_signature) =
            aggregate_member_signatures(&member_signatures, self.manifest.members.len())
                .map_err(|e| anyhow!(e.to_string()))?;

        Ok(GuardianQuorumCertificate {
            manifest_hash: self.manifest_hash,
            epoch: self.manifest.epoch,
            decision_hash,
            counter: decision.counter,
            trace_hash: decision.trace_hash,
            measurement_root: decision.measurement_root,
            signers_bitfield,
            aggregated_signature,
            log_checkpoint: None,
            experimental_witness_certificate: None,
        })
    }

    async fn collect_remote_signatures(
        &self,
        decision: &GuardianDecision,
        decision_hash: [u8; 32],
        slot: Option<(u64, u64)>,
        needed_signatures: usize,
    ) -> Result<Vec<(usize, BlsSignature)>> {
        if needed_signatures == 0 {
            return Ok(Vec::new());
        }

        let decision_bytes =
            codec::to_bytes_canonical(decision).map_err(|e| anyhow!(e.to_string()))?;
        let rpc_timeout = Self::remote_rpc_timeout();
        let mut inflight = FuturesUnordered::new();
        for remote_member in &self.remote_members {
            let endpoint = remote_member.endpoint.clone();
            let channel = remote_member.channel.clone();
            let manifest_hash = self.manifest_hash;
            let decision_bytes = decision_bytes.clone();
            inflight.push(async move {
                let request = SignCommitteeDecisionRequest {
                    decision: decision_bytes,
                    manifest_hash: manifest_hash.to_vec(),
                    height: slot.map(|(height, _)| height).unwrap_or_default(),
                    view: slot.map(|(_, view)| view).unwrap_or_default(),
                };
                let mut last_error = None;
                for attempt in 0..4 {
                    let mut client = GuardianControlClient::new(channel.clone());
                    match tokio::time::timeout(
                        rpc_timeout,
                        client.sign_committee_decision(request.clone()),
                    )
                    .await
                    {
                        Ok(Ok(response)) => return Ok::<_, anyhow::Error>(response.into_inner()),
                        Ok(Err(error)) => {
                            last_error = Some(anyhow!("{endpoint}: {error}"));
                        }
                        Err(_) => {
                            last_error = Some(anyhow!(
                                "{endpoint}: committee RPC timed out after {} ms",
                                rpc_timeout.as_millis()
                            ));
                        }
                    }
                    if attempt < 3 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
                Err(last_error.unwrap_or_else(|| anyhow!("{endpoint}: committee RPC failed")))
            });
        }

        let mut collected = Vec::new();
        while let Some(result) = inflight.next().await {
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        target: "guardian",
                        event = "committee_remote_sign_failed",
                        error = %error
                    );
                    continue;
                }
            };
            let manifest_hash: [u8; 32] =
                response.manifest_hash.as_slice().try_into().map_err(|_| {
                    anyhow!("remote committee response returned invalid manifest hash")
                })?;
            if manifest_hash != self.manifest_hash {
                return Err(anyhow!("remote committee response manifest hash mismatch"));
            }
            let returned_decision_hash: [u8; 32] =
                response.decision_hash.as_slice().try_into().map_err(|_| {
                    anyhow!("remote committee response returned invalid decision hash")
                })?;
            if returned_decision_hash != decision_hash {
                return Err(anyhow!("remote committee response decision hash mismatch"));
            }
            for partial_signature in response.partial_signatures {
                let verified =
                    self.verify_remote_partial_signature(decision_hash, partial_signature)?;
                if collected
                    .iter()
                    .any(|(member_index, _)| *member_index == verified.0)
                {
                    continue;
                }
                collected.push(verified);
                if collected.len() >= needed_signatures {
                    return Ok(collected);
                }
            }
        }

        Ok(collected)
    }

    fn verify_remote_partial_signature(
        &self,
        decision_hash: [u8; 32],
        partial_signature: GuardianMemberSignature,
    ) -> Result<(usize, BlsSignature)> {
        let member_index = usize::try_from(partial_signature.member_index)
            .map_err(|_| anyhow!("remote committee response member index overflow"))?;
        let member = self
            .manifest
            .members
            .get(member_index)
            .ok_or_else(|| anyhow!("remote committee response signer outside manifest"))?;
        let signature = BlsSignature::from_bytes(&partial_signature.signature)
            .map_err(|e| anyhow!(e.to_string()))?;
        let public_key =
            BlsPublicKey::from_bytes(&member.public_key).map_err(|e| anyhow!(e.to_string()))?;
        public_key
            .verify(&decision_hash, &signature)
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok((member_index, signature))
    }
}

impl GuardianWitnessCommitteeClient {
    fn from_configs(config: &GuardianConfig) -> Result<HashMap<[u8; 32], Self>> {
        let mut committees = HashMap::new();
        for witness_config in &config.experimental_witness_committees {
            if witness_config.members.is_empty() {
                continue;
            }
            if witness_config.threshold == 0 {
                return Err(anyhow!(
                    "experimental witness committee '{}' threshold must be at least 1",
                    witness_config.committee_id
                ));
            }
            if usize::from(witness_config.threshold) > witness_config.members.len() {
                return Err(anyhow!(
                    "experimental witness committee '{}' threshold {} exceeds member count {}",
                    witness_config.committee_id,
                    witness_config.threshold,
                    witness_config.members.len()
                ));
            }
            if usize::from(witness_config.threshold) <= witness_config.members.len() / 2 {
                return Err(anyhow!(
                    "experimental witness committee '{}' threshold {} must be a strict majority for size {}",
                    witness_config.committee_id,
                    witness_config.threshold,
                    witness_config.members.len()
                ));
            }
            if matches!(config.production_mode, GuardianProductionMode::Production)
                && witness_config.members.len() % 2 != 0
            {
                return Err(anyhow!(
                    "production witness committees must be even-sized; '{}' has {} members",
                    witness_config.committee_id,
                    witness_config.members.len()
                ));
            }

            let policy_hash = witness_config.policy_hash.unwrap_or(digest_to_array(
                Sha256::digest(&serde_json::to_vec(&(
                    &witness_config.committee_id,
                    witness_config.epoch,
                    witness_config.threshold,
                    &config.verifier_policy,
                    &config.transparency_log,
                ))?)
                .map_err(|e| anyhow!(e))?,
            )?);
            let manifest = GuardianWitnessCommitteeManifest {
                committee_id: witness_config.committee_id.clone(),
                stratum_id: witness_config.stratum_id.clone(),
                epoch: witness_config.epoch,
                threshold: witness_config.threshold,
                members: witness_config
                    .members
                    .iter()
                    .map(|member| GuardianCommitteeMember {
                        member_id: member.member_id.clone(),
                        signature_suite: SignatureSuite::BLS12_381,
                        public_key: member.public_key.clone(),
                        endpoint: member.endpoint.clone(),
                        provider: member.provider.clone(),
                        region: member.region.clone(),
                        host_class: member.host_class.clone(),
                        key_authority_kind: member.key_authority_kind,
                    })
                    .collect(),
                policy_hash,
                transparency_log_id: witness_config.transparency_log_id.clone(),
            };

            let mut signer_keys = Vec::new();
            let mut remote_members = Vec::new();
            for (index, member) in witness_config.members.iter().enumerate() {
                if let Some(path) = &member.private_key_path {
                    signer_keys.push((index, load_bls_private_key(Path::new(path))?));
                } else if let Some(endpoint) = &member.endpoint {
                    let endpoint = normalize_guardian_endpoint(endpoint);
                    remote_members.push(RemoteCommitteeMember {
                        channel: Channel::from_shared(endpoint.clone())?.connect_lazy(),
                        endpoint,
                    });
                }
            }

            if signer_keys.len() + remote_members.len() < usize::from(manifest.threshold) {
                return Err(anyhow!(
                    "experimental witness committee '{}' has {} reachable local/remote members but threshold is {}",
                    manifest.committee_id,
                    signer_keys.len() + remote_members.len(),
                    manifest.threshold
                ));
            }

            let manifest_hash =
                canonical_witness_manifest_hash(&manifest).map_err(|e| anyhow!(e.to_string()))?;
            committees.insert(
                manifest_hash,
                Self {
                    manifest,
                    manifest_hash,
                    signer_keys,
                    remote_members,
                },
            );
        }
        Ok(committees)
    }

    async fn sign_witness_statement(
        &self,
        statement: &GuardianWitnessStatement,
        reassignment_depth: u8,
        recovery_share_envelope: Option<&AssignedRecoveryShareEnvelopeV1>,
    ) -> Result<GuardianWitnessCertificate> {
        let statement_hash =
            canonical_witness_statement_hash(statement).map_err(|e| anyhow!(e.to_string()))?;
        let mut member_signatures = BTreeMap::<usize, BlsSignature>::new();

        for (member_index, signing_key) in &self.signer_keys {
            let signature = signing_key
                .sign(&statement_hash)
                .map_err(|e| anyhow!(e.to_string()))?;
            member_signatures.insert(*member_index, signature);
        }

        let threshold = usize::from(self.manifest.threshold);
        if member_signatures.len() < threshold {
            let remote_signatures = self
                .collect_remote_signatures(
                    statement,
                    statement_hash,
                    threshold.saturating_sub(member_signatures.len()),
                    recovery_share_envelope,
                )
                .await?;
            for (member_index, signature) in remote_signatures {
                member_signatures.entry(member_index).or_insert(signature);
                if member_signatures.len() >= threshold {
                    break;
                }
            }
        }

        if member_signatures.len() < threshold {
            return Err(anyhow!(
                "experimental witness committee '{}' collected {} signatures but threshold is {}",
                self.manifest.committee_id,
                member_signatures.len(),
                self.manifest.threshold
            ));
        }

        let member_signatures = member_signatures.into_iter().collect::<Vec<_>>();
        let (signers_bitfield, aggregated_signature) =
            aggregate_member_signatures(&member_signatures, self.manifest.members.len())
                .map_err(|e| anyhow!(e.to_string()))?;

        Ok(GuardianWitnessCertificate {
            manifest_hash: self.manifest_hash,
            stratum_id: self.manifest.stratum_id.clone(),
            epoch: self.manifest.epoch,
            statement_hash,
            signers_bitfield,
            aggregated_signature,
            reassignment_depth,
            recovery_binding: statement.recovery_binding.clone(),
            log_checkpoint: None,
        })
    }

    async fn collect_remote_signatures(
        &self,
        statement: &GuardianWitnessStatement,
        statement_hash: [u8; 32],
        needed_signatures: usize,
        recovery_share_envelope: Option<&AssignedRecoveryShareEnvelopeV1>,
    ) -> Result<Vec<(usize, BlsSignature)>> {
        if needed_signatures == 0 {
            return Ok(Vec::new());
        }

        let statement_bytes =
            codec::to_bytes_canonical(statement).map_err(|e| anyhow!(e.to_string()))?;
        let recovery_share_envelope_bytes = recovery_share_envelope
            .map(codec::to_bytes_canonical)
            .transpose()
            .map_err(|e| anyhow!(e.to_string()))?
            .unwrap_or_default();
        let rpc_timeout = GuardianCommitteeClient::remote_rpc_timeout();
        let mut inflight = FuturesUnordered::new();
        for remote_member in &self.remote_members {
            let endpoint = remote_member.endpoint.clone();
            let channel = remote_member.channel.clone();
            let manifest_hash = self.manifest_hash;
            let statement_bytes = statement_bytes.clone();
            let recovery_share_envelope = recovery_share_envelope_bytes.clone();
            inflight.push(async move {
                let request = SignWitnessStatementRequest {
                    statement: statement_bytes,
                    manifest_hash: manifest_hash.to_vec(),
                    recovery_share_envelope,
                };
                let mut last_error = None;
                for attempt in 0..4 {
                    let mut client = GuardianControlClient::new(channel.clone());
                    match tokio::time::timeout(
                        rpc_timeout,
                        client.sign_witness_statement(request.clone()),
                    )
                    .await
                    {
                        Ok(Ok(response)) => return Ok::<_, anyhow::Error>(response.into_inner()),
                        Ok(Err(error)) => {
                            last_error = Some(anyhow!("{endpoint}: {error}"));
                        }
                        Err(_) => {
                            last_error = Some(anyhow!(
                                "{endpoint}: witness RPC timed out after {} ms",
                                rpc_timeout.as_millis()
                            ));
                        }
                    }
                    if attempt < 3 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
                Err(last_error.unwrap_or_else(|| anyhow!("{endpoint}: witness RPC failed")))
            });
        }

        let mut collected = Vec::new();
        while let Some(result) = inflight.next().await {
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        target: "guardian",
                        event = "witness_remote_sign_failed",
                        error = %error
                    );
                    continue;
                }
            };
            let manifest_hash: [u8; 32] =
                response.manifest_hash.as_slice().try_into().map_err(|_| {
                    anyhow!("remote witness response returned invalid manifest hash")
                })?;
            if manifest_hash != self.manifest_hash {
                return Err(anyhow!("remote witness response manifest hash mismatch"));
            }
            let returned_statement_hash: [u8; 32] =
                response.statement_hash.as_slice().try_into().map_err(|_| {
                    anyhow!("remote witness response returned invalid statement hash")
                })?;
            if returned_statement_hash != statement_hash {
                return Err(anyhow!("remote witness response statement hash mismatch"));
            }
            for partial_signature in response.partial_signatures {
                let verified =
                    self.verify_remote_partial_signature(statement_hash, partial_signature)?;
                if collected
                    .iter()
                    .any(|(member_index, _)| *member_index == verified.0)
                {
                    continue;
                }
                collected.push(verified);
                if collected.len() >= needed_signatures {
                    return Ok(collected);
                }
            }
        }

        Ok(collected)
    }

    fn verify_remote_partial_signature(
        &self,
        statement_hash: [u8; 32],
        partial_signature: GuardianMemberSignature,
    ) -> Result<(usize, BlsSignature)> {
        let member_index = usize::try_from(partial_signature.member_index)
            .map_err(|_| anyhow!("remote witness response member index overflow"))?;
        let member = self
            .manifest
            .members
            .get(member_index)
            .ok_or_else(|| anyhow!("remote witness response signer outside manifest"))?;
        let signature = BlsSignature::from_bytes(&partial_signature.signature)
            .map_err(|e| anyhow!(e.to_string()))?;
        let public_key =
            BlsPublicKey::from_bytes(&member.public_key).map_err(|e| anyhow!(e.to_string()))?;
        public_key
            .verify(&statement_hash, &signature)
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok((member_index, signature))
    }
}

fn load_bls_private_key(path: &Path) -> Result<BlsPrivateKey> {
    let key_bytes = std::fs::read(path)?;
    if let Ok(raw_text) = std::str::from_utf8(&key_bytes) {
        let trimmed = raw_text.trim();
        let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if !trimmed.is_empty() && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return BlsPrivateKey::from_bytes(&hex::decode(trimmed)?)
                .map_err(|e| anyhow!(e.to_string()));
        }
    }
    BlsPrivateKey::from_bytes(&key_bytes).map_err(|e| anyhow!(e.to_string()))
}

/// gRPC-backed signer that delegates consensus certification to the local Guardian runtime.
pub struct GuardianGrpcSigner {
    channel: Channel,
    public_key: Vec<u8>,
    subject: Vec<u8>,
    manifest_hash: [u8; 32],
    measurement_root: [u8; 32],
    policy_hash: [u8; 32],
    checkpoint: Arc<TokioMutex<GuardianDecisionState>>,
}

impl GuardianGrpcSigner {
    /// Connects to the Guardian control-plane endpoint and prepares a signer handle.
    pub async fn connect(endpoint: String, public_key: Vec<u8>, subject: Vec<u8>) -> Result<Self> {
        let endpoint = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint
        } else {
            format!("http://{endpoint}")
        };
        let endpoint_config = Channel::from_shared(endpoint.clone())?;
        let mut last_error = None;
        let mut channel = None;
        for attempt in 0..20 {
            match endpoint_config.clone().connect().await {
                Ok(connected) => {
                    channel = Some(connected);
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    if attempt < 19 {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        }
        let channel = channel.ok_or_else(|| {
            let error = last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "guardian gRPC connection failed".to_string());
            anyhow!("failed to connect to guardian control endpoint {endpoint}: {error}")
        })?;
        Ok(Self {
            channel,
            public_key,
            subject,
            manifest_hash: [0u8; 32],
            measurement_root: [0u8; 32],
            policy_hash: [0u8; 32],
            checkpoint: Arc::new(TokioMutex::new(GuardianDecisionState::default())),
        })
    }
}

#[async_trait]
impl GuardianSigner for GuardianGrpcSigner {
    async fn sign_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        height: u64,
        view: u64,
        experimental_witness_manifest: Option<([u8; 32], u8)>,
        experimental_recovery_binding: Option<GuardianWitnessRecoveryBinding>,
    ) -> Result<SignatureBundle> {
        let checkpoint = self.checkpoint.lock().await.clone();
        let request = SignConsensusRequest {
            payload_hash: payload_hash.to_vec(),
            subject: self.subject.clone(),
            expected_counter: checkpoint.counter,
            expected_trace_hash: checkpoint.trace_hash.to_vec(),
            measurement_root: self.measurement_root.to_vec(),
            policy_hash: self.policy_hash.to_vec(),
            manifest_hash: self.manifest_hash.to_vec(),
            height,
            view,
            witness_manifest_hash: experimental_witness_manifest
                .map(|(manifest_hash, _)| manifest_hash.to_vec())
                .unwrap_or_default(),
            witness_reassignment_depth: experimental_witness_manifest
                .map(|(_, depth)| u32::from(depth))
                .unwrap_or_default(),
            recovery_capsule_hash: experimental_recovery_binding
                .as_ref()
                .map(|binding| binding.recovery_capsule_hash.to_vec())
                .unwrap_or_default(),
            share_commitment_hash: experimental_recovery_binding
                .as_ref()
                .map(|binding| binding.share_commitment_hash.to_vec())
                .unwrap_or_default(),
        };

        let mut client = GuardianControlClient::new(self.channel.clone());
        let response = client.sign_consensus(request).await?.into_inner();
        let trace_hash: [u8; 32] = response
            .trace_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("guardian returned invalid trace hash length"))?;
        let guardian_certificate = if response.guardian_certificate.is_empty() {
            None
        } else {
            Some(
                codec::from_bytes_canonical(&response.guardian_certificate)
                    .map_err(|e| anyhow!(e.to_string()))?,
            )
        };

        *self.checkpoint.lock().await = GuardianDecisionState {
            counter: response.counter,
            trace_hash,
            slot_locks: HashMap::new(),
            slot_certificates: HashMap::new(),
        };

        Ok(SignatureBundle {
            signature: response.signature,
            counter: response.counter,
            trace_hash,
            guardian_certificate,
            sealed_finality_proof: None,
        })
    }

    async fn seal_consensus_payload(
        &self,
        payload_hash: [u8; 32],
        height: u64,
        view: u64,
        witness_manifest_hashes: Vec<[u8; 32]>,
        witness_recovery_bindings: Vec<GuardianWitnessRecoveryBindingAssignment>,
        witness_recovery_share_envelopes: Vec<AssignedRecoveryShareEnvelopeV1>,
        observer_plan: Vec<AsymptoteObserverPlanEntry>,
        policy: AsymptotePolicy,
    ) -> Result<SealedFinalityProof> {
        let checkpoint = self.checkpoint.lock().await.clone();
        let request = SealConsensusRequest {
            payload_hash: payload_hash.to_vec(),
            subject: self.subject.clone(),
            expected_counter: checkpoint.counter,
            expected_trace_hash: checkpoint.trace_hash.to_vec(),
            measurement_root: self.measurement_root.to_vec(),
            policy_hash: self.policy_hash.to_vec(),
            manifest_hash: self.manifest_hash.to_vec(),
            height,
            view,
            witness_manifest_hashes: witness_manifest_hashes
                .into_iter()
                .map(|manifest_hash| manifest_hash.to_vec())
                .collect(),
            witness_reassignment_depth: 0,
            witness_recovery_bindings: witness_recovery_bindings
                .into_iter()
                .map(|binding| {
                    codec::to_bytes_canonical(&binding).map_err(|e| anyhow!(e.to_string()))
                })
                .collect::<Result<Vec<_>>>()?,
            witness_recovery_share_envelopes: witness_recovery_share_envelopes
                .into_iter()
                .map(|envelope| {
                    codec::to_bytes_canonical(&envelope).map_err(|e| anyhow!(e.to_string()))
                })
                .collect::<Result<Vec<_>>>()?,
            observer_plan_entries: observer_plan
                .into_iter()
                .map(|entry| codec::to_bytes_canonical(&entry).map_err(|e| anyhow!(e.to_string())))
                .collect::<Result<Vec<_>>>()?,
            asymptote_policy: codec::to_bytes_canonical(&policy)
                .map_err(|e| anyhow!(e.to_string()))?,
        };

        let mut client = GuardianControlClient::new(self.channel.clone());
        let response = client.seal_consensus(request).await?.into_inner();
        let trace_hash: [u8; 32] = response
            .trace_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("guardian returned invalid trace hash length"))?;
        *self.checkpoint.lock().await = GuardianDecisionState {
            counter: response.counter,
            trace_hash,
            slot_locks: HashMap::new(),
            slot_certificates: HashMap::new(),
        };

        codec::from_bytes_canonical(&response.sealed_finality_proof)
            .map_err(|e| anyhow!(e.to_string()))
    }

    async fn load_assigned_recovery_share_material(
        &self,
        height: u64,
        witness_manifest_hash: [u8; 32],
        recovery_binding: GuardianWitnessRecoveryBinding,
    ) -> Result<Option<RecoveryShareMaterial>> {
        let mut client = GuardianControlClient::new(self.channel.clone());
        let response = client
            .load_assigned_recovery_share(LoadAssignedRecoveryShareRequest {
                height,
                manifest_hash: witness_manifest_hash.to_vec(),
                recovery_capsule_hash: recovery_binding.recovery_capsule_hash.to_vec(),
                share_commitment_hash: recovery_binding.share_commitment_hash.to_vec(),
            })
            .await?
            .into_inner();
        if response.recovery_share_material.is_empty() {
            return Ok(None);
        }
        codec::from_bytes_canonical(&response.recovery_share_material)
            .map(Some)
            .map_err(|e| anyhow!(e.to_string()))
    }

    async fn report_witness_fault(&self, evidence: &GuardianWitnessFaultEvidence) -> Result<()> {
        let mut client = GuardianControlClient::new(self.channel.clone());
        client
            .report_witness_fault(ReportWitnessFaultRequest {
                evidence: codec::to_bytes_canonical(evidence)
                    .map_err(|e| anyhow!(e.to_string()))?,
            })
            .await?;
        Ok(())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}
