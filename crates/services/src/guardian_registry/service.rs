use super::*;

#[async_trait]
impl BlockchainService for GuardianRegistry {
    fn id(&self) -> &str {
        "guardian_registry"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "guardian_registry/v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "register_guardian_transparency_log@v1" => {
                let descriptor: GuardianTransparencyLogDescriptor =
                    codec::from_bytes_canonical(params)?;
                self.validate_log_descriptor(&descriptor)?;
                state.insert(
                    &guardian_registry_log_key(&descriptor.log_id),
                    &codec::to_bytes_canonical(&descriptor)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "register_guardian_committee@v1" => {
                let manifest: GuardianCommitteeManifest = codec::from_bytes_canonical(params)?;
                self.validate_committee_manifest(&manifest)?;
                let manifest_hash = Self::manifest_hash(&manifest)?;
                state.insert(
                    &guardian_registry_committee_key(&manifest_hash),
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )?;
                state.insert(
                    &guardian_registry_committee_account_key(&manifest.validator_account_id),
                    manifest_hash.as_ref(),
                )?;
                Ok(())
            }
            "publish_measurement_profile@v1" => {
                let profile: GuardianMeasurementProfile = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_MEASUREMENT_PREFIX,
                        profile.profile_id.as_bytes(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&profile)
                        .map_err(TransactionError::Serialization)?,
                )?;
                if profile.profile_id == "default" {
                    state.insert(
                        &[GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, b"default"].concat(),
                        &codec::to_bytes_canonical(&profile)
                            .map_err(TransactionError::Serialization)?,
                    )?;
                }
                Ok(())
            }
            "register_guardian_witness_committee@v1" => {
                let manifest: GuardianWitnessCommitteeManifest =
                    codec::from_bytes_canonical(params)?;
                self.validate_witness_manifest(&manifest)?;
                let manifest_hash = sha256(
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )
                .map_err(|e| TransactionError::Invalid(e.to_string()))
                .and_then(|digest| {
                    digest.try_into().map_err(|_| {
                        TransactionError::Invalid("invalid witness manifest hash length".into())
                    })
                })?;
                state.insert(
                    &guardian_registry_witness_key(&manifest_hash),
                    &codec::to_bytes_canonical(&manifest)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let active_key = guardian_registry_witness_set_key(manifest.epoch);
                let mut active_set = match state.get(&active_key)? {
                    Some(bytes) => codec::from_bytes_canonical::<GuardianWitnessSet>(&bytes)?,
                    None => GuardianWitnessSet {
                        epoch: manifest.epoch,
                        manifest_hashes: Vec::new(),
                        checkpoint_interval_blocks: 1,
                    },
                };
                if !active_set.manifest_hashes.contains(&manifest_hash) {
                    active_set.manifest_hashes.push(manifest_hash);
                    active_set.manifest_hashes.sort_unstable();
                }
                state.insert(
                    &active_key,
                    &codec::to_bytes_canonical(&active_set)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_witness_epoch_seed@v1" => {
                let seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(params)?;
                state.insert(
                    &guardian_registry_witness_seed_key(seed.epoch),
                    &codec::to_bytes_canonical(&seed).map_err(TransactionError::Serialization)?,
                )?;
                let active_key = guardian_registry_witness_set_key(seed.epoch);
                let mut active_set = match state.get(&active_key)? {
                    Some(bytes) => codec::from_bytes_canonical::<GuardianWitnessSet>(&bytes)?,
                    None => GuardianWitnessSet {
                        epoch: seed.epoch,
                        manifest_hashes: Vec::new(),
                        checkpoint_interval_blocks: seed.checkpoint_interval_blocks,
                    },
                };
                active_set.checkpoint_interval_blocks = seed.checkpoint_interval_blocks;
                state.insert(
                    &active_key,
                    &codec::to_bytes_canonical(&active_set)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_policy@v1" => {
                let policy: AsymptotePolicy = codec::from_bytes_canonical(params)?;
                let witness_mode = !policy.required_witness_strata.is_empty()
                    || !policy.escalation_witness_strata.is_empty();
                let observer_mode =
                    policy.observer_rounds > 0 || policy.observer_committee_size > 0;
                if !witness_mode && !observer_mode {
                    return Err(TransactionError::Invalid(
                        "asymptote policy requires either witness strata or equal-authority observer sampling".into(),
                    ));
                }
                if observer_mode
                    && (policy.observer_rounds == 0 || policy.observer_committee_size == 0)
                {
                    return Err(TransactionError::Invalid(
                        "asymptote equal-authority observer mode requires non-zero rounds and committee size".into(),
                    ));
                }
                if matches!(
                    policy.observer_sealing_mode,
                    AsymptoteObserverSealingMode::CanonicalChallengeV1
                ) && !observer_mode
                {
                    return Err(TransactionError::Invalid(
                        "canonical observer sealing mode requires equal-authority observer assignments"
                            .into(),
                    ));
                }
                if matches!(
                    policy.observer_sealing_mode,
                    AsymptoteObserverSealingMode::CanonicalChallengeV1
                ) && policy.observer_challenge_window_ms == 0
                {
                    return Err(TransactionError::Invalid(
                        "canonical observer sealing mode requires a non-zero challenge window"
                            .into(),
                    ));
                }
                if witness_mode {
                    if policy.required_witness_strata.is_empty() {
                        return Err(TransactionError::Invalid(
                            "asymptote witness mode requires at least one base witness stratum"
                                .into(),
                        ));
                    }
                    let required = policy
                        .required_witness_strata
                        .iter()
                        .map(|stratum| stratum.trim())
                        .collect::<std::collections::BTreeSet<_>>();
                    let escalation = policy
                        .escalation_witness_strata
                        .iter()
                        .map(|stratum| stratum.trim())
                        .collect::<std::collections::BTreeSet<_>>();
                    if required.contains("") || escalation.contains("") {
                        return Err(TransactionError::Invalid(
                            "asymptote witness strata must not be empty".into(),
                        ));
                    }
                    if required.len() != policy.required_witness_strata.len()
                        || escalation.len() != policy.escalation_witness_strata.len()
                    {
                        return Err(TransactionError::Invalid(
                            "asymptote witness strata must be unique".into(),
                        ));
                    }
                    if !required.is_subset(&escalation) {
                        return Err(TransactionError::Invalid(
                            "asymptote escalation strata must include all base strata".into(),
                        ));
                    }
                }
                if policy.max_checkpoint_staleness_ms > 0
                    && policy.max_checkpoint_staleness_ms < self.config.max_checkpoint_staleness_ms
                {
                    return Err(TransactionError::Invalid(
                        "asymptote checkpoint staleness cannot be weaker than guardian registry policy"
                            .into(),
                    ));
                }
                state.insert(
                    &guardian_registry_asymptote_policy_key(policy.epoch),
                    &codec::to_bytes_canonical(&policy).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_transcript_commitment@v1" => {
                let commitment: AsymptoteObserverTranscriptCommitment =
                    codec::from_bytes_canonical(params)?;
                if commitment.epoch == 0 || commitment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer transcript commitment requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_transcript_commitment_key(
                        commitment.epoch,
                        commitment.height,
                        commitment.view,
                    ),
                    &codec::to_bytes_canonical(&commitment)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_transcript@v1" => {
                let transcript: AsymptoteObserverTranscript = codec::from_bytes_canonical(params)?;
                if transcript.statement.epoch == 0 || transcript.statement.assignment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer transcript requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_transcript_key(
                        transcript.statement.epoch,
                        transcript.statement.assignment.height,
                        transcript.statement.assignment.view,
                        transcript.statement.assignment.round,
                        &transcript.statement.assignment.observer_account_id,
                    ),
                    &codec::to_bytes_canonical(&transcript)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_challenge_commitment@v1" => {
                let commitment: AsymptoteObserverChallengeCommitment =
                    codec::from_bytes_canonical(params)?;
                if commitment.epoch == 0 || commitment.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer challenge commitment requires non-zero epoch and height".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_observer_challenge_commitment_key(
                        commitment.epoch,
                        commitment.height,
                        commitment.view,
                    ),
                    &codec::to_bytes_canonical(&commitment)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_asymptote_observer_challenge@v1" => {
                let challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(params)?;
                if challenge.epoch == 0
                    || challenge.height == 0
                    || challenge.challenge_id == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "observer challenge requires non-zero epoch, height, and challenge id"
                            .into(),
                    ));
                }
                Self::validate_observer_challenge_shape(&challenge)?;
                state.insert(
                    &guardian_registry_observer_challenge_key(
                        challenge.epoch,
                        challenge.height,
                        challenge.view,
                        &challenge.challenge_id,
                    ),
                    &codec::to_bytes_canonical(&challenge)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Self::refresh_observer_challenge_surface(state, &challenge)?;
                if let Some(report) = Self::observer_challenge_failure_report(&challenge)? {
                    Self::apply_accountable_fault_report(
                        state,
                        report,
                        ctx.block_height,
                        self.config.apply_accountable_membership_updates,
                    )?;
                }
                Ok(())
            }
            "publish_asymptote_observer_canonical_close@v1" => {
                let close: AsymptoteObserverCanonicalClose = codec::from_bytes_canonical(params)?;
                if close.epoch == 0 || close.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer canonical close requires non-zero epoch and height".into(),
                    ));
                }
                if let Some(existing_abort) = Self::load_asymptote_observer_canonical_abort(
                    state,
                    close.epoch,
                    close.height,
                    close.view,
                )? {
                    return Err(TransactionError::Invalid(format!(
                        "cannot publish observer canonical close after canonical abort is already persisted for {}/{}/{}",
                        existing_abort.epoch, existing_abort.height, existing_abort.view
                    )));
                }
                if let Some(existing_commitment) =
                    Self::load_asymptote_observer_challenge_commitment(
                        state,
                        close.epoch,
                        close.height,
                        close.view,
                    )?
                {
                    if existing_commitment.challenge_count > 0 {
                        return Err(TransactionError::Invalid(
                            "cannot publish observer canonical close once the stored challenge surface is non-empty"
                                .into(),
                        ));
                    }
                }
                if let Some(existing_close) = Self::load_asymptote_observer_canonical_close(
                    state,
                    close.epoch,
                    close.height,
                    close.view,
                )? {
                    if existing_close != close {
                        return Err(TransactionError::Invalid(
                            "conflicting observer canonical close already published for slot"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &guardian_registry_observer_canonical_close_key(
                        close.epoch,
                        close.height,
                        close.view,
                    ),
                    &codec::to_bytes_canonical(&close).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_asymptote_observer_canonical_abort@v1" => {
                let abort: AsymptoteObserverCanonicalAbort = codec::from_bytes_canonical(params)?;
                if abort.epoch == 0 || abort.height == 0 {
                    return Err(TransactionError::Invalid(
                        "observer canonical abort requires non-zero epoch and height".into(),
                    ));
                }
                if let Some(existing_abort) = Self::load_asymptote_observer_canonical_abort(
                    state,
                    abort.epoch,
                    abort.height,
                    abort.view,
                )? {
                    if existing_abort != abort {
                        return Err(TransactionError::Invalid(
                            "conflicting observer canonical abort already published for slot"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                Self::materialize_observer_abort(state, abort)?;
                Ok(())
            }
            "register_effect_proof_verifier@v1" => {
                let verifier: EffectProofVerifierDescriptor = codec::from_bytes_canonical(params)?;
                if verifier.verifier_id.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "effect proof verifier id must not be empty".into(),
                    ));
                }
                state.insert(
                    &guardian_registry_effect_verifier_key(&verifier.verifier_id),
                    &codec::to_bytes_canonical(&verifier)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "record_sealed_effect@v1" => {
                let record: SealedEffectRecord = codec::from_bytes_canonical(params)?;
                if record.nullifier == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "sealed effect nullifier must be non-zero".into(),
                    ));
                }
                if record.intent_hash == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "sealed effect intent hash must be non-zero".into(),
                    ));
                }
                if record.verifier_id.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "sealed effect verifier id must not be empty".into(),
                    ));
                }
                let bytes =
                    codec::to_bytes_canonical(&record).map_err(TransactionError::Serialization)?;
                state.insert(
                    &guardian_registry_effect_nullifier_key(&record.nullifier),
                    &bytes,
                )?;
                state.insert(
                    &guardian_registry_sealed_effect_key(&record.intent_hash),
                    &bytes,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_commitment@v1" => {
                let bulletin: BulletinCommitment = codec::from_bytes_canonical(params)?;
                if bulletin.height == 0 {
                    return Err(TransactionError::Invalid(
                        "aft bulletin commitment height must be non-zero".into(),
                    ));
                }
                if bulletin.bulletin_root == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "aft bulletin commitment root must be non-zero".into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_commitment_key(bulletin.height),
                    &codec::to_bytes_canonical(&bulletin)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_entry@v1" => {
                let entry: BulletinSurfaceEntry = codec::from_bytes_canonical(params)?;
                if entry.height == 0 || entry.tx_hash == [0u8; 32] {
                    return Err(TransactionError::Invalid(
                        "aft bulletin entry requires non-zero height and tx hash".into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                    &codec::to_bytes_canonical(&entry).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_bulletin_availability_certificate@v1" => {
                let certificate: BulletinAvailabilityCertificate =
                    codec::from_bytes_canonical(params)?;
                if certificate.height == 0
                    || certificate.bulletin_commitment_hash == [0u8; 32]
                    || certificate.recoverability_root == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft bulletin availability certificate requires non-zero height and roots"
                            .into(),
                    ));
                }
                state.insert(
                    &aft_bulletin_availability_certificate_key(certificate.height),
                    &codec::to_bytes_canonical(&certificate)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_publication_frontier@v1" => {
                let frontier: PublicationFrontier = codec::from_bytes_canonical(params)?;
                if frontier.height == 0
                    || frontier.counter == 0
                    || frontier.bulletin_commitment_hash == [0u8; 32]
                    || frontier.ordered_transactions_root_hash == [0u8; 32]
                    || frontier.availability_receipt_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft publication frontier requires non-zero height, counter, and compact commitments"
                            .into(),
                    ));
                }
                if Self::load_publication_frontier_contradiction(state, frontier.height)?.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "cannot publish a positive publication frontier after a contradiction already dominates the slot"
                            .into(),
                    ));
                }
                if let Some(existing_abort) =
                    Self::load_canonical_order_abort(state, frontier.height)?
                {
                    return Err(TransactionError::Invalid(format!(
                        "cannot publish a positive publication frontier after canonical-order abort publication: {}",
                        existing_abort.details
                    )));
                }
                if let Some(existing) = Self::load_publication_frontier(state, frontier.height)? {
                    if existing != frontier {
                        Self::materialize_publication_frontier_contradiction(
                            state,
                            PublicationFrontierContradiction {
                                height: frontier.height,
                                kind: PublicationFrontierContradictionKind::ConflictingFrontier,
                                candidate_frontier: frontier,
                                reference_frontier: existing,
                            },
                        )?;
                    }
                    return Ok(());
                }
                if frontier.height > 1 {
                    if let Some(previous) =
                        Self::load_publication_frontier(state, frontier.height - 1)?
                    {
                        let expected_parent_hash = canonical_publication_frontier_hash(&previous)
                            .map_err(TransactionError::Invalid)?;
                        if frontier.counter != previous.counter.saturating_add(1)
                            || frontier.parent_frontier_hash != expected_parent_hash
                        {
                            Self::materialize_publication_frontier_contradiction(
                                state,
                                PublicationFrontierContradiction {
                                    height: frontier.height,
                                    kind: PublicationFrontierContradictionKind::StaleParentLink,
                                    candidate_frontier: frontier,
                                    reference_frontier: previous,
                                },
                            )?;
                            return Ok(());
                        }
                    }
                }
                state.insert(
                    &aft_publication_frontier_key(frontier.height),
                    &codec::to_bytes_canonical(&frontier)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_recovery_capsule@v1" => {
                let capsule: RecoveryCapsule = codec::from_bytes_canonical(params)?;
                if capsule.height == 0
                    || capsule.coding.recovery_threshold == 0
                    || capsule.recovery_committee_root_hash == [0u8; 32]
                    || capsule.payload_commitment_hash == [0u8; 32]
                    || capsule.coding_root_hash == [0u8; 32]
                    || capsule.recovery_window_close_ms == 0
                {
                    return Err(TransactionError::Invalid(
                        "aft recovery capsule requires non-zero height, threshold, roots, and recovery window"
                            .into(),
                    ));
                }
                if let Some(existing) = Self::load_recovery_capsule(state, capsule.height)? {
                    if existing != capsule {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovery capsule already published for height".into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &aft_recovery_capsule_key(capsule.height),
                    &codec::to_bytes_canonical(&capsule)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_recovery_witness_certificate@v1" => {
                let certificate: RecoveryWitnessCertificate = codec::from_bytes_canonical(params)?;
                if certificate.height == 0
                    || certificate.witness_manifest_hash == [0u8; 32]
                    || certificate.recovery_capsule_hash == [0u8; 32]
                    || certificate.share_commitment_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft recovery witness certificate requires non-zero height, witness manifest, capsule, and share commitment"
                            .into(),
                    ));
                }
                let capsule =
                    Self::load_recovery_capsule(state, certificate.height)?.ok_or_else(|| {
                        TransactionError::Invalid(
                            "aft recovery witness certificate requires a published recovery capsule"
                                .into(),
                        )
                    })?;
                let expected_capsule_hash =
                    canonical_recovery_capsule_hash(&capsule).map_err(TransactionError::Invalid)?;
                if certificate.recovery_capsule_hash != expected_capsule_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery witness certificate must bind the published recovery capsule"
                            .into(),
                    ));
                }
                let key = aft_recovery_witness_certificate_key(
                    certificate.height,
                    &certificate.witness_manifest_hash,
                );
                if let Some(existing) = Self::load_recovery_witness_certificate(
                    state,
                    certificate.height,
                    &certificate.witness_manifest_hash,
                )? {
                    if existing != certificate {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovery witness certificate already published for witness manifest"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&certificate)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_recovery_share_receipt@v1" => {
                let receipt: RecoveryShareReceipt = codec::from_bytes_canonical(params)?;
                if receipt.height == 0
                    || receipt.witness_manifest_hash == [0u8; 32]
                    || receipt.block_commitment_hash == [0u8; 32]
                    || receipt.share_commitment_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft recovery share receipt requires non-zero height, witness manifest, block commitment, and share commitment"
                            .into(),
                    ));
                }
                let certificate = Self::load_recovery_witness_certificate(
                    state,
                    receipt.height,
                    &receipt.witness_manifest_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft recovery share receipt requires a published recovery witness certificate"
                            .into(),
                    )
                })?;
                if certificate.share_commitment_hash != receipt.share_commitment_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery share receipt must match the witness certificate share commitment"
                            .into(),
                    ));
                }
                if certificate.witness_manifest_hash != receipt.witness_manifest_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery share receipt must bind the witness manifest carried by the witness certificate"
                            .into(),
                    ));
                }
                if Self::load_missing_recovery_share(
                    state,
                    receipt.height,
                    &receipt.witness_manifest_hash,
                )?
                .is_some()
                {
                    return Err(TransactionError::Invalid(
                        "cannot publish an aft recovery share receipt after missing-share publication"
                            .into(),
                    ));
                }
                let key = aft_recovery_share_receipt_key(
                    receipt.height,
                    &receipt.witness_manifest_hash,
                    &receipt.block_commitment_hash,
                );
                if let Some(existing) = state.get(&key)? {
                    let existing: RecoveryShareReceipt = codec::from_bytes_canonical(&existing)
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != receipt {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovery share receipt already published for witness and block"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&receipt)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Self::materialize_recovery_impossible_abort_if_needed(state, receipt.height)?;
                Ok(())
            }
            "publish_aft_recovery_share_material@v1" => {
                let material: RecoveryShareMaterial = codec::from_bytes_canonical(params)?;
                if material.height == 0
                    || material.witness_manifest_hash == [0u8; 32]
                    || material.block_commitment_hash == [0u8; 32]
                    || material.share_commitment_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft recovery share material requires non-zero height, witness manifest, block commitment, and share commitment"
                            .into(),
                    ));
                }
                let certificate = Self::load_recovery_witness_certificate(
                    state,
                    material.height,
                    &material.witness_manifest_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft recovery share material requires a published recovery witness certificate"
                            .into(),
                    )
                })?;
                if certificate.share_commitment_hash != material.share_commitment_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery share material must match the witness certificate share commitment"
                            .into(),
                    ));
                }
                if certificate.witness_manifest_hash != material.witness_manifest_hash {
                    return Err(TransactionError::Invalid(
                        "aft recovery share material must bind the witness manifest carried by the witness certificate"
                            .into(),
                    ));
                }
                if Self::load_missing_recovery_share(
                    state,
                    material.height,
                    &material.witness_manifest_hash,
                )?
                .is_some()
                {
                    return Err(TransactionError::Invalid(
                        "cannot publish aft recovery share material after missing-share publication"
                            .into(),
                    ));
                }
                let expected_receipt = material.to_recovery_share_receipt();
                let receipt_key = aft_recovery_share_receipt_key(
                    material.height,
                    &material.witness_manifest_hash,
                    &material.block_commitment_hash,
                );
                let receipt_bytes = state.get(&receipt_key)?.ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft recovery share material requires a published matching recovery share receipt"
                            .into(),
                    )
                })?;
                let receipt: RecoveryShareReceipt = codec::from_bytes_canonical(&receipt_bytes)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                if receipt != expected_receipt {
                    return Err(TransactionError::Invalid(
                        "aft recovery share material must match the published recovery share receipt"
                            .into(),
                    ));
                }
                let key = aft_recovery_share_material_key(
                    material.height,
                    &material.witness_manifest_hash,
                    &material.block_commitment_hash,
                );
                if let Some(existing) = state.get(&key)? {
                    let existing: RecoveryShareMaterial = codec::from_bytes_canonical(&existing)
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != material {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovery share material already published for witness and block"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&material)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_recovered_publication_bundle@v1" => {
                let recovered: RecoveredPublicationBundle = codec::from_bytes_canonical(params)?;
                if recovered.height == 0
                    || recovered.block_commitment_hash == [0u8; 32]
                    || recovered.coding.recovery_threshold == 0
                    || recovered.recoverable_slot_payload_hash == [0u8; 32]
                    || recovered.recoverable_full_surface_hash == [0u8; 32]
                    || recovered.canonical_order_publication_bundle_hash == [0u8; 32]
                    || recovered.canonical_bulletin_close_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft recovered publication bundle requires non-zero height, block commitment, threshold, v4 hash, v5 hash, publication-bundle hash, and bulletin-close hash"
                            .into(),
                    ));
                }
                let normalized_witnesses =
                    normalize_recovered_publication_bundle_supporting_witnesses(
                        &recovered.supporting_witness_manifest_hashes,
                    )
                    .map_err(TransactionError::Invalid)?;
                if normalized_witnesses != recovered.supporting_witness_manifest_hashes {
                    return Err(TransactionError::Invalid(
                        "aft recovered publication bundle must carry canonical sorted supporting witness manifests"
                            .into(),
                    ));
                }
                if normalized_witnesses.len() != usize::from(recovered.coding.recovery_threshold) {
                    return Err(TransactionError::Invalid(
                        "aft recovered publication bundle supporting witness count must match the recovery threshold"
                            .into(),
                    ));
                }

                let materials =
                    Self::load_supporting_recovery_share_materials_for_recovered_bundle(
                        state, &recovered,
                    )
                    .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                let (_, full_surface, bundle, bulletin_close) =
                    Self::reconstruct_recovered_publication_surface(&recovered, &materials)
                        .map_err(|error| TransactionError::Invalid(error.to_string()))?;

                let key = aft_recovered_publication_bundle_key(
                    recovered.height,
                    &recovered.block_commitment_hash,
                    &recovered.supporting_witness_manifest_hashes,
                )
                .map_err(TransactionError::Invalid)?;
                let recovered_bytes = codec::to_bytes_canonical(&recovered)
                    .map_err(TransactionError::Serialization)?;
                let conflicting_existing =
                    Self::load_recovered_publication_bundles_for_height(state, recovered.height)?
                        .into_iter()
                        .find(|existing| {
                            Self::recovered_publication_bundle_conflicts(existing, &recovered)
                        });
                if let Some(existing) = state.get(&key)? {
                    let existing: RecoveredPublicationBundle =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != recovered {
                        return Err(TransactionError::Invalid(
                            "conflicting aft recovered publication bundle already published for the same support set"
                                .into(),
                        ));
                    }
                    if conflicting_existing.is_none() {
                        return Ok(());
                    }
                } else {
                    state.insert(&key, &recovered_bytes)?;
                }
                if let Some(existing) = conflicting_existing {
                    let abort = Self::build_canonical_order_abort(
                        recovered.height,
                        CanonicalOrderAbortReason::RecoverySupportConflict,
                        format!(
                            "published recovered publication bundle conflicts with an existing recovered slot surface for height {}",
                            existing.height
                        ),
                        None,
                        None,
                    );
                    Self::materialize_canonical_order_abort(state, abort)?;
                    return Ok(());
                }
                self.materialize_canonical_order_publication_bundle(
                    state,
                    &bundle,
                    &bulletin_close,
                    ctx,
                )?;
                let previous_collapse = if full_surface.height <= 1 {
                    None
                } else {
                    Self::load_canonical_collapse_object(state, full_surface.height - 1)?
                };
                let recovered_collapse = derive_canonical_collapse_object_from_recovered_surface(
                    &full_surface,
                    &bulletin_close,
                    previous_collapse.as_ref(),
                )
                .map_err(TransactionError::Invalid)?;
                let mut recovered_collapse = recovered_collapse;
                if let Some((checkpoint_hash, activation_hash, receipt_hash)) =
                    Self::load_latest_canonical_archived_history_anchor_hashes(state)?
                {
                    set_canonical_collapse_archived_recovered_history_anchor(
                        &mut recovered_collapse,
                        checkpoint_hash,
                        activation_hash,
                        receipt_hash,
                    )
                    .map_err(TransactionError::Invalid)?;
                }
                Self::materialize_canonical_collapse_object(state, recovered_collapse)?;
                state.insert(&key, &recovered_bytes)?;
                Ok(())
            }
            "publish_aft_archived_recovered_history_segment@v1" => {
                let segment: ArchivedRecoveredHistorySegment = codec::from_bytes_canonical(params)?;
                let segment_hash = canonical_archived_recovered_history_segment_hash(&segment)
                    .map_err(TransactionError::Invalid)?;
                if segment.start_height == 0
                    || segment.end_height == 0
                    || segment.end_height < segment.start_height
                    || segment.archived_profile_hash == [0u8; 32]
                    || segment.archived_profile_activation_hash == [0u8; 32]
                    || segment.first_recovered_publication_bundle_hash == [0u8; 32]
                    || segment.last_recovered_publication_bundle_hash == [0u8; 32]
                    || segment.segment_root_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history segment requires a valid height range, non-zero archived profile hash, non-zero archived profile activation hash, first/last recovered bundle hashes, and segment root"
                            .into(),
                    ));
                }
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &segment.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history segment requires its archived profile to be published first"
                            .into(),
                    )
                })?;
                validate_archived_recovered_history_segment_against_profile(&segment, &profile)
                    .map_err(TransactionError::Invalid)?;
                Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
                    state,
                    &segment.archived_profile_activation_hash,
                    &segment.archived_profile_hash,
                    segment.end_height,
                )
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                if (segment.overlap_start_height == 0) != (segment.overlap_end_height == 0) {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history segment overlap heights must both be zero or both be non-zero"
                            .into(),
                    ));
                }
                if segment.overlap_start_height == 0 {
                    if segment.overlap_root_hash != [0u8; 32] {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered-history segment without an overlap range must use the zero overlap root"
                                .into(),
                        ));
                    }
                } else if segment.overlap_end_height < segment.overlap_start_height
                    || segment.overlap_start_height < segment.start_height
                    || segment.overlap_end_height > segment.end_height
                    || segment.overlap_root_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history segment overlap range must lie within the covered range and carry a non-zero overlap root"
                            .into(),
                    ));
                }
                let key = aft_archived_recovered_history_segment_key(
                    segment.start_height,
                    segment.end_height,
                );
                let hash_key = aft_archived_recovered_history_segment_hash_key(&segment_hash);
                let segment_bytes =
                    codec::to_bytes_canonical(&segment).map_err(TransactionError::Serialization)?;

                if let Some(existing) = state.get(&hash_key)? {
                    let existing: ArchivedRecoveredHistorySegment =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != segment {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history segment already published for the same segment hash"
                                .into(),
                        ));
                    }
                }

                if let Some(existing) = state.get(&key)? {
                    let existing: ArchivedRecoveredHistorySegment =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != segment {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history segment already published for the same covered range"
                                .into(),
                        ));
                    }
                    if state.get(&hash_key)?.is_none() {
                        state.insert(&hash_key, &segment_bytes)?;
                    }
                    return Ok(());
                }
                state.insert(&key, &segment_bytes)?;
                state.insert(&hash_key, &segment_bytes)?;
                Ok(())
            }
            "publish_aft_archived_recovered_history_profile@v1" => {
                let profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(params)?;
                let expected = build_archived_recovered_history_profile(
                    profile.retention_horizon,
                    profile.restart_page_window,
                    profile.restart_page_overlap,
                    profile.windows_per_segment,
                    profile.segments_per_fold,
                    profile.checkpoint_update_rule,
                )
                .map_err(TransactionError::Invalid)?;
                if expected != profile {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history profile is not canonically normalized"
                            .into(),
                    ));
                }
                validate_archived_recovered_history_profile(&profile)
                    .map_err(TransactionError::Invalid)?;
                let profile_hash = canonical_archived_recovered_history_profile_hash(&profile)
                    .map_err(TransactionError::Invalid)?;
                let profile_bytes =
                    codec::to_bytes_canonical(&profile).map_err(TransactionError::Serialization)?;
                let hash_key = aft_archived_recovered_history_profile_hash_key(&profile_hash);

                if let Some(existing) = state.get(&hash_key)? {
                    let existing: ArchivedRecoveredHistoryProfile =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != profile {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history profile already published for the same profile hash"
                                .into(),
                        ));
                    }
                } else {
                    state.insert(&hash_key, &profile_bytes)?;
                }
                Ok(())
            }
            "publish_aft_archived_recovered_history_profile_activation@v1" => {
                let activation: ArchivedRecoveredHistoryProfileActivation =
                    codec::from_bytes_canonical(params)?;
                if activation.archived_profile_hash == [0u8; 32]
                    || activation.activation_end_height == 0
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history profile activation requires a non-zero profile hash and activation end height"
                            .into(),
                    ));
                }
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &activation.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history profile activation requires the referenced archived profile to be published first"
                            .into(),
                    )
                })?;
                validate_archived_recovered_history_profile_activation(&activation, &profile)
                    .map_err(TransactionError::Invalid)?;

                let existing_by_profile = Self::load_archived_recovered_history_profile_activation(
                    state,
                    &activation.archived_profile_hash,
                )?;
                if let Some(existing) = existing_by_profile.as_ref() {
                    if existing != &activation {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history profile activation already published for the same profile hash"
                                .into(),
                        ));
                    }
                }

                let existing_by_height =
                    Self::load_archived_recovered_history_profile_activation_for_end_height(
                        state,
                        activation.activation_end_height,
                    )?;
                if let Some(existing) = existing_by_height.as_ref() {
                    if existing != &activation {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history profile activation already published for the same activation end height"
                                .into(),
                        ));
                    }
                }

                let activation_checkpoint = if activation.activation_checkpoint_hash == [0u8; 32] {
                    None
                } else {
                    let checkpoint =
                        Self::load_archived_recovered_history_checkpoint_by_hash(
                            state,
                            &activation.activation_checkpoint_hash,
                        )?
                        .ok_or_else(|| {
                            TransactionError::Invalid(
                                "aft archived recovered-history profile activation requires its activation checkpoint to be published first"
                                    .into(),
                            )
                        })?;
                    if checkpoint.archived_profile_hash != activation.archived_profile_hash {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered-history profile activation checkpoint profile hash does not match the activated profile"
                                .into(),
                        ));
                    }
                    if checkpoint.covered_end_height != activation.activation_end_height {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered-history profile activation checkpoint tip does not match the declared activation end height"
                                .into(),
                        ));
                    }
                    Some(checkpoint)
                };

                let latest_activation =
                    Self::load_latest_archived_recovered_history_profile_activation(state)?;
                if existing_by_profile.is_none() && existing_by_height.is_none() {
                    if let Some(previous_activation) = latest_activation.as_ref() {
                        validate_archived_recovered_history_profile_activation_successor(
                            previous_activation,
                            &activation,
                        )
                        .map_err(TransactionError::Invalid)?;
                    } else if activation.previous_archived_profile_hash != [0u8; 32] {
                        return Err(TransactionError::Invalid(
                            "bootstrap aft archived recovered-history profile activation must use the zero previous profile hash"
                                .into(),
                        ));
                    }
                    let expected = build_archived_recovered_history_profile_activation(
                        &profile,
                        latest_activation.as_ref(),
                        activation.activation_end_height,
                        activation_checkpoint.as_ref(),
                    )
                    .map_err(TransactionError::Invalid)?;
                    if expected != activation {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered-history profile activation is not canonically normalized"
                                .into(),
                        ));
                    }
                }

                let activation_key = aft_archived_recovered_history_profile_activation_key(
                    &activation.archived_profile_hash,
                );
                let height_key = aft_archived_recovered_history_profile_activation_height_key(
                    activation.activation_end_height,
                );
                let activation_hash =
                    canonical_archived_recovered_history_profile_activation_hash(&activation)
                        .map_err(TransactionError::Invalid)?;
                let hash_key =
                    aft_archived_recovered_history_profile_activation_hash_key(&activation_hash);
                let activation_bytes = codec::to_bytes_canonical(&activation)
                    .map_err(TransactionError::Serialization)?;
                if state.get(&activation_key)?.is_none() {
                    state.insert(&activation_key, &activation_bytes)?;
                }
                if state.get(&height_key)?.is_none() {
                    state.insert(&height_key, &activation_bytes)?;
                }
                if state.get(&hash_key)?.is_none() {
                    state.insert(&hash_key, &activation_bytes)?;
                }

                match latest_activation {
                    Some(existing_latest) if existing_latest == activation => {}
                    Some(_existing_latest) if existing_by_profile.is_some() => {}
                    Some(existing_latest) => {
                        if activation.activation_end_height <= existing_latest.activation_end_height
                        {
                            return Err(TransactionError::Invalid(
                                "aft archived recovered-history profile activation must advance beyond the current latest activation tip"
                                    .into(),
                            ));
                        }
                        state.insert(
                            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
                            &activation_bytes,
                        )?;
                    }
                    None => {
                        state.insert(
                            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
                            &activation_bytes,
                        )?;
                    }
                }

                let profile_bytes =
                    codec::to_bytes_canonical(&profile).map_err(TransactionError::Serialization)?;
                state.insert(
                    AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
                    &profile_bytes,
                )?;
                Ok(())
            }
            "publish_aft_archived_recovered_restart_page@v1" => {
                let page: ArchivedRecoveredRestartPage = codec::from_bytes_canonical(params)?;
                if page.segment_hash == [0u8; 32]
                    || page.archived_profile_hash == [0u8; 32]
                    || page.archived_profile_activation_hash == [0u8; 32]
                    || page.start_height == 0
                    || page.end_height == 0
                    || page.end_height < page.start_height
                    || page.restart_headers.is_empty()
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page requires a non-zero segment hash, archived profile hash, archived profile activation hash, valid range, and at least one restart header"
                            .into(),
                    ));
                }
                if page.restart_headers[0].header.height != page.start_height
                    || page
                        .restart_headers
                        .last()
                        .map(|entry| entry.header.height)
                        .ok_or_else(|| {
                            TransactionError::Invalid(
                                "aft archived recovered restart page is missing its end height"
                                    .into(),
                            )
                        })?
                        != page.end_height
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page heights do not match the archived page range"
                            .into(),
                    ));
                }
                for pair in page.restart_headers.windows(2) {
                    if pair[1].header.height != pair[0].header.height + 1 {
                        return Err(TransactionError::Invalid(
                            "aft archived recovered restart page requires contiguous restart-header heights"
                                .into(),
                        ));
                    }
                }

                let Some(segment) = Self::load_archived_recovered_history_segment_by_hash(
                    state,
                    &page.segment_hash,
                )?
                else {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page requires the archived segment descriptor to be published first"
                            .into(),
                    ));
                };
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &page.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered restart page requires its archived profile to be published first"
                            .into(),
                    )
                })?;
                if segment.archived_profile_hash != page.archived_profile_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page profile hash does not match the archived segment descriptor"
                            .into(),
                    ));
                }
                if segment.archived_profile_activation_hash != page.archived_profile_activation_hash
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page activation hash does not match the archived segment descriptor"
                            .into(),
                    ));
                }
                validate_archived_recovered_restart_page_against_profile(&page, &profile)
                    .map_err(TransactionError::Invalid)?;
                Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
                    state,
                    &page.archived_profile_activation_hash,
                    &page.archived_profile_hash,
                    page.end_height,
                )
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                let expected_page =
                    build_archived_recovered_restart_page(&segment, &page.restart_headers)
                        .map_err(TransactionError::Invalid)?;
                if expected_page != page {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered restart page does not match the archived segment range or segment hash"
                            .into(),
                    ));
                }

                let key = aft_archived_recovered_restart_page_key(&page.segment_hash);
                if let Some(existing) = state.get(&key)? {
                    let existing: ArchivedRecoveredRestartPage =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != page {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered restart page already published for the same segment hash"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&page).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "publish_aft_archived_recovered_history_checkpoint@v1" => {
                let checkpoint: ArchivedRecoveredHistoryCheckpoint =
                    codec::from_bytes_canonical(params)?;
                if checkpoint.covered_start_height == 0
                    || checkpoint.covered_end_height == 0
                    || checkpoint.covered_end_height < checkpoint.covered_start_height
                    || checkpoint.archived_profile_hash == [0u8; 32]
                    || checkpoint.archived_profile_activation_hash == [0u8; 32]
                    || checkpoint.latest_archived_segment_hash == [0u8; 32]
                    || checkpoint.latest_archived_restart_page_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint requires a valid covered range, non-zero archived profile hash, non-zero archived profile activation hash, and non-zero segment/page hashes"
                            .into(),
                    ));
                }
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &checkpoint.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history checkpoint requires its archived profile to be published first"
                            .into(),
                    )
                })?;
                validate_archived_recovered_history_checkpoint_against_profile(
                    &checkpoint,
                    &profile,
                )
                .map_err(TransactionError::Invalid)?;
                Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
                    state,
                    &checkpoint.archived_profile_activation_hash,
                    &checkpoint.archived_profile_hash,
                    checkpoint.covered_end_height,
                )
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;

                let Some(segment) = Self::load_archived_recovered_history_segment_by_hash(
                    state,
                    &checkpoint.latest_archived_segment_hash,
                )?
                else {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint requires the archived segment descriptor to be published first"
                            .into(),
                    ));
                };
                if segment.start_height != checkpoint.covered_start_height
                    || segment.end_height != checkpoint.covered_end_height
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint covered range does not match the archived segment descriptor"
                            .into(),
                    ));
                }
                if segment.archived_profile_hash != checkpoint.archived_profile_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint profile hash does not match the archived segment descriptor"
                            .into(),
                    ));
                }
                if segment.archived_profile_activation_hash
                    != checkpoint.archived_profile_activation_hash
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint activation hash does not match the archived segment descriptor"
                            .into(),
                    ));
                }

                let Some(page) = Self::load_archived_recovered_restart_page(
                    state,
                    &checkpoint.latest_archived_segment_hash,
                )?
                else {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint requires the archived restart page to be published first"
                            .into(),
                    ));
                };
                if page.start_height != checkpoint.covered_start_height
                    || page.end_height != checkpoint.covered_end_height
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint covered range does not match the archived restart page"
                            .into(),
                    ));
                }
                if page.archived_profile_hash != checkpoint.archived_profile_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint profile hash does not match the archived restart page"
                            .into(),
                    ));
                }
                if page.archived_profile_activation_hash
                    != checkpoint.archived_profile_activation_hash
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint activation hash does not match the archived restart page"
                            .into(),
                    ));
                }
                let page_hash = canonical_archived_recovered_restart_page_hash(&page)
                    .map_err(TransactionError::Invalid)?;
                if page_hash != checkpoint.latest_archived_restart_page_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint page hash does not match the archived restart page"
                            .into(),
                    ));
                }

                let previous_checkpoint = if checkpoint.previous_archived_checkpoint_hash
                    == [0u8; 32]
                {
                    None
                } else {
                    Some(
                        Self::load_archived_recovered_history_checkpoint_by_hash(
                            state,
                            &checkpoint.previous_archived_checkpoint_hash,
                        )?
                        .ok_or_else(|| {
                            TransactionError::Invalid(
                                "aft archived recovered-history checkpoint predecessor is missing from state"
                                    .into(),
                            )
                        })?,
                    )
                };
                let expected = build_archived_recovered_history_checkpoint(
                    &segment,
                    &page,
                    previous_checkpoint.as_ref(),
                )
                .map_err(TransactionError::Invalid)?;
                if expected != checkpoint {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history checkpoint does not match the archived tip segment/page surface"
                            .into(),
                    ));
                }

                let checkpoint_hash =
                    canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
                        .map_err(TransactionError::Invalid)?;
                let key = aft_archived_recovered_history_checkpoint_key(
                    checkpoint.covered_start_height,
                    checkpoint.covered_end_height,
                );
                let hash_key = aft_archived_recovered_history_checkpoint_hash_key(&checkpoint_hash);
                let checkpoint_bytes = codec::to_bytes_canonical(&checkpoint)
                    .map_err(TransactionError::Serialization)?;

                if let Some(existing) = state.get(&hash_key)? {
                    let existing: ArchivedRecoveredHistoryCheckpoint =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != checkpoint {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history checkpoint already published for the same checkpoint hash"
                                .into(),
                        ));
                    }
                }

                if let Some(existing) = state.get(&key)? {
                    let existing: ArchivedRecoveredHistoryCheckpoint =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != checkpoint {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history checkpoint already published for the same covered range"
                                .into(),
                        ));
                    }
                } else {
                    state.insert(&key, &checkpoint_bytes)?;
                }
                if state.get(&hash_key)?.is_none() {
                    state.insert(&hash_key, &checkpoint_bytes)?;
                }

                if let Some(existing_latest_bytes) =
                    state.get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)?
                {
                    let existing_latest: ArchivedRecoveredHistoryCheckpoint =
                        codec::from_bytes_canonical(&existing_latest_bytes)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing_latest == checkpoint {
                        return Ok(());
                    }
                    if existing_latest.covered_end_height == checkpoint.covered_end_height {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history checkpoint already published for the same latest tip height"
                                .into(),
                        ));
                    }
                    if checkpoint.covered_end_height > existing_latest.covered_end_height {
                        let existing_latest_hash =
                            canonical_archived_recovered_history_checkpoint_hash(&existing_latest)
                                .map_err(TransactionError::Invalid)?;
                        if checkpoint.previous_archived_checkpoint_hash != existing_latest_hash {
                            return Err(TransactionError::Invalid(
                                "aft archived recovered-history checkpoint advance must chain from the current latest checkpoint"
                                    .into(),
                            ));
                        }
                        state.insert(
                            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY,
                            &checkpoint_bytes,
                        )?;
                    }
                    return Ok(());
                }

                state.insert(
                    AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY,
                    &checkpoint_bytes,
                )?;
                Ok(())
            }
            "publish_aft_archived_recovered_history_retention_receipt@v1" => {
                let receipt: ArchivedRecoveredHistoryRetentionReceipt =
                    codec::from_bytes_canonical(params)?;
                if receipt.covered_start_height == 0
                    || receipt.covered_end_height == 0
                    || receipt.covered_end_height < receipt.covered_start_height
                    || receipt.archived_profile_hash == [0u8; 32]
                    || receipt.archived_profile_activation_hash == [0u8; 32]
                    || receipt.archived_checkpoint_hash == [0u8; 32]
                    || receipt.validator_set_commitment_hash == [0u8; 32]
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt requires a valid covered range, archived profile hash, archived profile activation hash, checkpoint hash, and validator-set commitment hash"
                            .into(),
                    ));
                }

                let checkpoint = Self::load_archived_recovered_history_checkpoint_by_hash(
                    state,
                    &receipt.archived_checkpoint_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history retention receipt requires the archived checkpoint to be published first"
                            .into(),
                    )
                })?;
                if checkpoint.covered_start_height != receipt.covered_start_height
                    || checkpoint.covered_end_height != receipt.covered_end_height
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt covered range does not match the archived checkpoint"
                            .into(),
                    ));
                }
                if checkpoint.archived_profile_hash != receipt.archived_profile_hash {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt profile hash does not match the archived checkpoint"
                            .into(),
                    ));
                }
                if checkpoint.archived_profile_activation_hash
                    != receipt.archived_profile_activation_hash
                {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt activation hash does not match the archived checkpoint"
                            .into(),
                    ));
                }
                let profile = Self::load_archived_recovered_history_profile_by_hash(
                    state,
                    &receipt.archived_profile_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft archived recovered-history retention receipt requires its archived profile to be published first"
                            .into(),
                    )
                })?;

                let Some(validator_set_bytes) = state.get(VALIDATOR_SET_KEY)? else {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt requires an active validator set"
                            .into(),
                    ));
                };
                let validator_sets = read_validator_sets(&validator_set_bytes)
                    .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                let validator_set_commitment_hash = canonical_validator_sets_hash(&validator_sets)
                    .map_err(TransactionError::Invalid)?;
                let expected = build_archived_recovered_history_retention_receipt(
                    &checkpoint,
                    validator_set_commitment_hash,
                    receipt.retained_through_height,
                )
                .map_err(TransactionError::Invalid)?;
                validate_archived_recovered_history_retention_receipt_against_profile(
                    &receipt,
                    &checkpoint,
                    &profile,
                )
                .map_err(TransactionError::Invalid)?;
                Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
                    state,
                    &receipt.archived_profile_activation_hash,
                    &receipt.archived_profile_hash,
                    receipt.covered_end_height,
                )
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
                if expected != receipt {
                    return Err(TransactionError::Invalid(
                        "aft archived recovered-history retention receipt does not match the archived checkpoint or current validator-set commitment"
                            .into(),
                    ));
                }

                let key = aft_archived_recovered_history_retention_receipt_key(
                    &receipt.archived_checkpoint_hash,
                );
                let receipt_bytes =
                    codec::to_bytes_canonical(&receipt).map_err(TransactionError::Serialization)?;
                if let Some(existing) = state.get(&key)? {
                    let existing: ArchivedRecoveredHistoryRetentionReceipt =
                        codec::from_bytes_canonical(&existing)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    if existing != receipt {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history retention receipt already published for the same archived checkpoint"
                                .into(),
                        ));
                    }
                    let existing_hash =
                        canonical_archived_recovered_history_retention_receipt_hash(&existing)
                            .map_err(TransactionError::Invalid)?;
                    let receipt_hash =
                        canonical_archived_recovered_history_retention_receipt_hash(&receipt)
                            .map_err(TransactionError::Invalid)?;
                    if existing_hash != receipt_hash {
                        return Err(TransactionError::Invalid(
                            "conflicting aft archived recovered-history retention receipt hash published for the same archived checkpoint"
                                .into(),
                        ));
                    }
                    return Ok(());
                }

                state.insert(&key, &receipt_bytes)?;
                Ok(())
            }
            "publish_aft_missing_recovery_share@v1" => {
                let missing: MissingRecoveryShare = codec::from_bytes_canonical(params)?;
                if missing.height == 0
                    || missing.witness_manifest_hash == [0u8; 32]
                    || missing.recovery_capsule_hash == [0u8; 32]
                    || missing.recovery_window_close_ms == 0
                {
                    return Err(TransactionError::Invalid(
                        "aft missing recovery share requires non-zero height, witness manifest, capsule, and recovery window"
                            .into(),
                    ));
                }
                let certificate = Self::load_recovery_witness_certificate(
                    state,
                    missing.height,
                    &missing.witness_manifest_hash,
                )?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "aft missing recovery share requires a published recovery witness certificate"
                            .into(),
                    )
                })?;
                if certificate.recovery_capsule_hash != missing.recovery_capsule_hash {
                    return Err(TransactionError::Invalid(
                        "aft missing recovery share must bind the witness certificate capsule"
                            .into(),
                    ));
                }
                if certificate.witness_manifest_hash != missing.witness_manifest_hash {
                    return Err(TransactionError::Invalid(
                        "aft missing recovery share must bind the witness manifest carried by the witness certificate"
                            .into(),
                    ));
                }
                let capsule =
                    Self::load_recovery_capsule(state, missing.height)?.ok_or_else(|| {
                        TransactionError::Invalid(
                            "aft missing recovery share requires a published recovery capsule"
                                .into(),
                        )
                    })?;
                let expected_capsule_hash =
                    canonical_recovery_capsule_hash(&capsule).map_err(TransactionError::Invalid)?;
                if missing.recovery_capsule_hash != expected_capsule_hash
                    || missing.recovery_window_close_ms != capsule.recovery_window_close_ms
                {
                    return Err(TransactionError::Invalid(
                        "aft missing recovery share must bind the published recovery capsule and recovery window"
                            .into(),
                    ));
                }
                if !Self::load_recovery_share_receipts(
                    state,
                    missing.height,
                    &missing.witness_manifest_hash,
                )?
                .is_empty()
                {
                    return Err(TransactionError::Invalid(
                        "cannot publish aft missing recovery share after a recovery receipt already exists"
                            .into(),
                    ));
                }
                let key =
                    aft_missing_recovery_share_key(missing.height, &missing.witness_manifest_hash);
                if let Some(existing) = Self::load_missing_recovery_share(
                    state,
                    missing.height,
                    &missing.witness_manifest_hash,
                )? {
                    if existing != missing {
                        return Err(TransactionError::Invalid(
                            "conflicting aft missing recovery share already published for witness manifest"
                                .into(),
                        ));
                    }
                    return Ok(());
                }
                state.insert(
                    &key,
                    &codec::to_bytes_canonical(&missing)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Self::materialize_recovery_impossible_abort_if_needed(state, missing.height)?;
                Ok(())
            }
            "publish_aft_canonical_order_artifact_bundle@v1" => {
                let bundle: CanonicalOrderPublicationBundle = codec::from_bytes_canonical(params)?;
                let bulletin_close = verify_canonical_order_publication_bundle(&bundle)
                    .map_err(TransactionError::Invalid)?;
                self.materialize_canonical_order_publication_bundle(
                    state,
                    &bundle,
                    &bulletin_close,
                    ctx,
                )
            }
            "publish_aft_bulletin_retrievability_challenge@v1" => {
                let challenge: BulletinRetrievabilityChallenge =
                    codec::from_bytes_canonical(params)?;
                if challenge.height == 0 {
                    return Err(TransactionError::Invalid(
                        "aft bulletin retrievability challenge requires non-zero height".into(),
                    ));
                }
                let bulletin_commitment = Self::load_bulletin_commitment(state, challenge.height)?
                    .ok_or_else(|| {
                        TransactionError::Invalid(
                            "aft bulletin retrievability challenge requires a published bulletin commitment"
                                .into(),
                        )
                    })?;
                let bulletin_availability_certificate =
                    Self::load_bulletin_availability_certificate(state, challenge.height)?
                        .ok_or_else(|| {
                            TransactionError::Invalid(
                                "aft bulletin retrievability challenge requires a published bulletin availability certificate"
                                    .into(),
                            )
                        })?;
                let profile = Self::load_bulletin_retrievability_profile(state, challenge.height)?;
                let manifest = Self::load_bulletin_shard_manifest(state, challenge.height)?;
                let assignment = Self::load_bulletin_custody_assignment(state, challenge.height)?;
                let receipt = Self::load_bulletin_custody_receipt(state, challenge.height)?;
                let response = Self::load_bulletin_custody_response(state, challenge.height)?;
                let entries = Self::load_bulletin_surface_entries(state, challenge.height)?;
                let validator_set =
                    Self::load_effective_validator_set_for_height(state, challenge.height)
                        .map_err(TransactionError::State)?;
                validate_bulletin_retrievability_challenge(
                    &challenge,
                    &bulletin_commitment,
                    &bulletin_availability_certificate,
                    profile.as_ref(),
                    manifest.as_ref(),
                    Some(&validator_set),
                    assignment.as_ref(),
                    receipt.as_ref(),
                    response.as_ref(),
                    &entries,
                )
                .map_err(TransactionError::Invalid)?;
                Self::materialize_bulletin_retrievability_challenge(state, &challenge)
            }
            "publish_aft_canonical_order_abort@v1" => {
                let abort: CanonicalOrderAbort = codec::from_bytes_canonical(params)?;
                if abort.height == 0 {
                    return Err(TransactionError::Invalid(
                        "aft canonical-order abort requires non-zero height".into(),
                    ));
                }
                Self::materialize_canonical_order_abort(state, abort)?;
                Ok(())
            }
            "publish_aft_canonical_collapse_object@v1" => {
                let collapse: CanonicalCollapseObject = codec::from_bytes_canonical(params)?;
                Self::materialize_canonical_collapse_object(state, collapse)
            }
            "publish_aft_order_certificate@v1" => {
                let _certificate: CanonicalOrderCertificate = codec::from_bytes_canonical(params)?;
                Err(TransactionError::Invalid(
                    "publish_aft_order_certificate@v1 is retired; publish_aft_canonical_order_artifact_bundle@v1 is required for positive canonical-order admission".into(),
                ))
            }
            "report_aft_omission@v1" => {
                let omission: OmissionProof = codec::from_bytes_canonical(params)?;
                if omission.height == 0
                    || omission.tx_hash == [0u8; 32]
                    || omission.offender_account_id == AccountId::default()
                {
                    return Err(TransactionError::Invalid(
                        "aft omission proof requires non-zero height, offender, and tx hash".into(),
                    ));
                }
                state.insert(
                    &aft_omission_proof_key(omission.height, &omission.tx_hash),
                    &codec::to_bytes_canonical(&omission)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let existing_certificate =
                    Self::load_canonical_order_certificate(state, omission.height)
                        .map_err(TransactionError::State)?;
                let existing_close = Self::load_canonical_bulletin_close(state, omission.height)
                    .map_err(TransactionError::State)?;
                let abort = Self::build_canonical_order_abort(
                    omission.height,
                    CanonicalOrderAbortReason::OmissionDominated,
                    omission.details.clone(),
                    existing_certificate.as_ref(),
                    existing_close.as_ref(),
                );
                Self::materialize_canonical_order_abort(state, abort)?;
                let report = Self::omission_failure_report(&omission)?;
                Self::apply_accountable_fault_report(
                    state,
                    report,
                    ctx.block_height,
                    self.config.apply_accountable_membership_updates,
                )?;
                Ok(())
            }
            "anchor_guardian_checkpoint@v1" => {
                let checkpoint: GuardianLogCheckpoint = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_CHECKPOINT_PREFIX,
                        checkpoint.log_id.as_bytes(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&checkpoint)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_guardian_equivocation@v1" => {
                let proof: ProofOfDivergence = codec::from_bytes_canonical(params)?;
                state.insert(
                    &[
                        GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX,
                        proof.offender.as_ref(),
                    ]
                    .concat(),
                    &codec::to_bytes_canonical(&proof).map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            "report_guardian_witness_fault@v1" => {
                let evidence: GuardianWitnessFaultEvidence = codec::from_bytes_canonical(params)?;
                state.insert(
                    &guardian_registry_witness_fault_key(&evidence.evidence_id),
                    &codec::to_bytes_canonical(&evidence)
                        .map_err(TransactionError::Serialization)?,
                )?;
                Ok(())
            }
            _ => Err(TransactionError::Unsupported(format!(
                "GuardianRegistry does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for GuardianRegistry {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}
