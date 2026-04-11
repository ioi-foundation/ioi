use super::*;

impl GuardianRegistry {
    pub(super) fn load_quarantined_validators(
        state: &dyn StateAccess,
    ) -> Result<BTreeSet<AccountId>, TransactionError> {
        let set = state
            .get(QUARANTINED_VALIDATORS_KEY)?
            .map(|bytes| codec::from_bytes_canonical(&bytes).map_err(StateError::InvalidValue))
            .transpose()
            .map_err(TransactionError::State)?;
        Ok(set.unwrap_or_default())
    }

    pub(super) fn load_evidence_registry(
        state: &dyn StateAccess,
    ) -> Result<BTreeSet<[u8; 32]>, TransactionError> {
        let set = state
            .get(EVIDENCE_REGISTRY_KEY)?
            .map(|bytes| codec::from_bytes_canonical(&bytes).map_err(StateError::InvalidValue))
            .transpose()
            .map_err(TransactionError::State)?;
        Ok(set.unwrap_or_default())
    }

    pub(super) fn build_canonical_order_abort(
        height: u64,
        reason: CanonicalOrderAbortReason,
        details: impl Into<String>,
        certificate: Option<&CanonicalOrderCertificate>,
        close: Option<&CanonicalBulletinClose>,
    ) -> CanonicalOrderAbort {
        let bulletin_commitment_hash = certificate
            .and_then(|candidate| {
                canonical_bulletin_commitment_hash(&candidate.bulletin_commitment).ok()
            })
            .unwrap_or([0u8; 32]);
        let bulletin_availability_certificate_hash = certificate
            .and_then(|candidate| {
                canonical_bulletin_availability_certificate_hash(
                    &candidate.bulletin_availability_certificate,
                )
                .ok()
            })
            .unwrap_or([0u8; 32]);
        let bulletin_close_hash = close
            .and_then(|candidate| canonical_bulletin_close_hash(candidate).ok())
            .unwrap_or([0u8; 32]);
        let canonical_order_certificate_hash = certificate
            .and_then(|candidate| canonical_order_certificate_hash(candidate).ok())
            .unwrap_or([0u8; 32]);
        CanonicalOrderAbort {
            height,
            reason,
            details: details.into(),
            bulletin_commitment_hash,
            bulletin_availability_certificate_hash,
            bulletin_close_hash,
            canonical_order_certificate_hash,
        }
    }

    pub(super) fn materialize_canonical_order_abort(
        state: &mut dyn StateAccess,
        abort: CanonicalOrderAbort,
    ) -> Result<(), TransactionError> {
        state.insert(
            &aft_canonical_order_abort_key(abort.height),
            &codec::to_bytes_canonical(&abort).map_err(TransactionError::Serialization)?,
        )?;
        state.delete(&aft_order_certificate_key(abort.height))?;
        state.delete(&aft_bulletin_availability_certificate_key(abort.height))?;
        state.delete(&aft_bulletin_retrievability_profile_key(abort.height))?;
        state.delete(&aft_bulletin_shard_manifest_key(abort.height))?;
        state.delete(&aft_bulletin_custody_assignment_key(abort.height))?;
        state.delete(&aft_bulletin_custody_receipt_key(abort.height))?;
        state.delete(&aft_bulletin_custody_response_key(abort.height))?;
        state.delete(&aft_bulletin_reconstruction_certificate_key(abort.height))?;
        state.delete(&aft_canonical_bulletin_close_key(abort.height))?;
        state.delete(&aft_publication_frontier_key(abort.height))?;

        if let Some(mut collapse) = Self::load_canonical_collapse_object(state, abort.height)
            .map_err(TransactionError::State)?
        {
            collapse.ordering.kind = CanonicalCollapseKind::Abort;
            if abort.bulletin_commitment_hash != [0u8; 32] {
                collapse.ordering.bulletin_commitment_hash = abort.bulletin_commitment_hash;
            }
            if abort.bulletin_availability_certificate_hash != [0u8; 32] {
                collapse.ordering.bulletin_availability_certificate_hash =
                    abort.bulletin_availability_certificate_hash;
            }
            if abort.bulletin_close_hash != [0u8; 32] {
                collapse.ordering.bulletin_close_hash = abort.bulletin_close_hash;
            }
            if abort.canonical_order_certificate_hash != [0u8; 32] {
                collapse.ordering.canonical_order_certificate_hash =
                    abort.canonical_order_certificate_hash;
            }
            let previous = if collapse.height <= 1 {
                None
            } else {
                Self::load_canonical_collapse_object(state, collapse.height - 1)
                    .map_err(TransactionError::State)?
            };
            bind_canonical_collapse_continuity(&mut collapse, previous.as_ref())
                .map_err(TransactionError::Invalid)?;
            state.insert(
                &aft_canonical_collapse_object_key(collapse.height),
                &codec::to_bytes_canonical(&collapse).map_err(TransactionError::Serialization)?,
            )?;
        }
        Ok(())
    }

    pub(super) fn materialize_canonical_collapse_object(
        state: &mut dyn StateAccess,
        collapse: CanonicalCollapseObject,
    ) -> Result<(), TransactionError> {
        if collapse.height == 0 {
            return Err(TransactionError::Invalid(
                "aft canonical collapse object requires non-zero height".into(),
            ));
        }
        if collapse.ordering.height != collapse.height {
            return Err(TransactionError::Invalid(
                "aft canonical collapse object ordering height must match slot height".into(),
            ));
        }
        if collapse.transactions_root_hash == [0u8; 32]
            || collapse.resulting_state_root_hash == [0u8; 32]
        {
            return Err(TransactionError::Invalid(
                "aft canonical collapse object requires non-zero transaction and state roots"
                    .into(),
            ));
        }
        if let Some(sealing) = collapse.sealing.as_ref() {
            if sealing.height != collapse.height {
                return Err(TransactionError::Invalid(
                    "aft canonical collapse object sealing height must match slot height".into(),
                ));
            }
        }
        Self::validate_canonical_collapse_archived_history_anchor(state, &collapse)?;
        match collapse.ordering.kind {
            CanonicalCollapseKind::Close => {
                if Self::load_canonical_order_abort(state, collapse.height)?.is_some() {
                    return Err(TransactionError::Invalid(
                        "cannot publish a close-valued canonical collapse object after canonical-order abort publication".into(),
                    ));
                }
            }
            CanonicalCollapseKind::Abort => {
                state.delete(&aft_order_certificate_key(collapse.height))?;
                state.delete(&aft_bulletin_availability_certificate_key(collapse.height))?;
                state.delete(&aft_bulletin_retrievability_profile_key(collapse.height))?;
                state.delete(&aft_bulletin_shard_manifest_key(collapse.height))?;
                state.delete(&aft_bulletin_custody_assignment_key(collapse.height))?;
                state.delete(&aft_bulletin_custody_receipt_key(collapse.height))?;
                state.delete(&aft_bulletin_custody_response_key(collapse.height))?;
                state.delete(&aft_bulletin_reconstruction_certificate_key(
                    collapse.height,
                ))?;
                state.delete(&aft_canonical_bulletin_close_key(collapse.height))?;
            }
        }
        if let Some(existing) = Self::load_canonical_collapse_object(state, collapse.height)? {
            let existing_has_abort = existing.ordering.kind == CanonicalCollapseKind::Abort
                || existing
                    .sealing
                    .as_ref()
                    .map(|sealing| sealing.kind == CanonicalCollapseKind::Abort)
                    .unwrap_or(false);
            let new_has_abort = collapse.ordering.kind == CanonicalCollapseKind::Abort
                || collapse
                    .sealing
                    .as_ref()
                    .map(|sealing| sealing.kind == CanonicalCollapseKind::Abort)
                    .unwrap_or(false);
            let anchor_only_upgrade =
                canonical_collapse_eq_ignoring_archived_recovered_history_anchor(
                    &existing, &collapse,
                ) && canonical_collapse_archived_recovered_history_anchor(&existing)
                    .map_err(TransactionError::Invalid)?
                    .is_none()
                    && canonical_collapse_archived_recovered_history_anchor(&collapse)
                        .map_err(TransactionError::Invalid)?
                        .is_some();
            let sealing_only_upgrade =
                ioi_types::app::canonical_collapse_eq_on_header_surface(&existing, &collapse)
                    && existing.sealing.is_none()
                    && collapse.sealing.is_some();
            if existing != collapse
                && !(new_has_abort && !existing_has_abort)
                && !anchor_only_upgrade
                && !sealing_only_upgrade
            {
                return Err(TransactionError::Invalid(
                    "conflicting canonical collapse object already published for height".into(),
                ));
            }
            if existing == collapse {
                return Ok(());
            }
        }
        let previous = if collapse.height <= 1 {
            None
        } else {
            Self::load_canonical_collapse_object(state, collapse.height - 1)?
        };
        verify_canonical_collapse_continuity(&collapse, previous.as_ref())
            .map_err(TransactionError::Invalid)?;
        state.insert(
            &aft_canonical_collapse_object_key(collapse.height),
            &codec::to_bytes_canonical(&collapse).map_err(TransactionError::Serialization)?,
        )?;
        Ok(())
    }

    pub(super) fn materialize_publication_frontier_contradiction(
        state: &mut dyn StateAccess,
        contradiction: PublicationFrontierContradiction,
    ) -> Result<(), TransactionError> {
        verify_publication_frontier_contradiction(&contradiction)
            .map_err(TransactionError::Invalid)?;
        state.insert(
            &aft_publication_frontier_contradiction_key(contradiction.height),
            &codec::to_bytes_canonical(&contradiction).map_err(TransactionError::Serialization)?,
        )?;
        let (reason, details) = match contradiction.kind {
            PublicationFrontierContradictionKind::ConflictingFrontier => (
                CanonicalOrderAbortReason::PublicationFrontierConflict,
                "published compact publication frontier conflicts with an existing same-slot frontier",
            ),
            PublicationFrontierContradictionKind::StaleParentLink => (
                CanonicalOrderAbortReason::PublicationFrontierStale,
                "published compact publication frontier does not extend the previous frontier",
            ),
        };
        let abort =
            Self::build_canonical_order_abort(contradiction.height, reason, details, None, None);
        Self::materialize_canonical_order_abort(state, abort)
    }

    pub(super) fn materialize_observer_abort(
        state: &mut dyn StateAccess,
        abort: AsymptoteObserverCanonicalAbort,
    ) -> Result<(), TransactionError> {
        state.delete(&guardian_registry_observer_canonical_close_key(
            abort.epoch,
            abort.height,
            abort.view,
        ))?;
        state.insert(
            &guardian_registry_observer_canonical_abort_key(abort.epoch, abort.height, abort.view),
            &codec::to_bytes_canonical(&abort).map_err(TransactionError::Serialization)?,
        )?;

        if let Some(mut collapse) = Self::load_canonical_collapse_object(state, abort.height)
            .map_err(TransactionError::State)?
        {
            if let Some(sealing) = collapse.sealing.as_mut() {
                if sealing.epoch == abort.epoch
                    && sealing.height == abort.height
                    && sealing.view == abort.view
                {
                    sealing.kind = CanonicalCollapseKind::Abort;
                    sealing.finality_tier = FinalityTier::BaseFinal;
                    sealing.collapse_state = CollapseState::Abort;
                    sealing.transcripts_root = abort.transcripts_root;
                    sealing.challenges_root = abort.challenges_root;
                    sealing.resolution_hash =
                        canonical_asymptote_observer_canonical_abort_hash(&abort)
                            .map_err(TransactionError::Invalid)?;
                    let previous = if collapse.height <= 1 {
                        None
                    } else {
                        Self::load_canonical_collapse_object(state, collapse.height - 1)
                            .map_err(TransactionError::State)?
                    };
                    bind_canonical_collapse_continuity(&mut collapse, previous.as_ref())
                        .map_err(TransactionError::Invalid)?;
                    state.insert(
                        &aft_canonical_collapse_object_key(collapse.height),
                        &codec::to_bytes_canonical(&collapse)
                            .map_err(TransactionError::Serialization)?,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn materialize_canonical_order_publication_bundle(
        &self,
        state: &mut dyn StateAccess,
        bundle: &CanonicalOrderPublicationBundle,
        bulletin_close: &CanonicalBulletinClose,
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        if Self::load_bulletin_retrievability_challenge(
            state,
            bundle.canonical_order_certificate.height,
        )?
        .is_some()
        {
            return Err(TransactionError::Invalid(
                "cannot admit a positive canonical-order bundle after retrievability challenge publication"
                    .into(),
            ));
        }
        if bundle
            .canonical_order_certificate
            .omission_proofs
            .is_empty()
            && Self::load_canonical_order_abort(state, bundle.canonical_order_certificate.height)?
                .is_some()
        {
            return Err(TransactionError::Invalid(
                "cannot admit a positive canonical-order bundle after canonical abort publication"
                    .into(),
            ));
        }

        validate_bulletin_retrievability_profile(
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_commitment,
            &bundle.bulletin_availability_certificate,
        )
        .map_err(TransactionError::Invalid)?;
        validate_bulletin_shard_manifest(
            &bundle.bulletin_shard_manifest,
            &bundle.bulletin_commitment,
            &bundle.bulletin_availability_certificate,
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_entries,
        )
        .map_err(TransactionError::Invalid)?;
        validate_bulletin_custody_receipt(
            &bundle.bulletin_custody_receipt,
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_shard_manifest,
        )
        .map_err(TransactionError::Invalid)?;
        let active_validator_set = Self::load_effective_validator_set_for_height(
            state,
            bundle.canonical_order_certificate.height,
        )
        .map_err(TransactionError::State)?;
        let custody_assignment = build_bulletin_custody_assignment(
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_shard_manifest,
            &active_validator_set,
        )
        .map_err(TransactionError::Invalid)?;
        validate_bulletin_custody_assignment(
            &custody_assignment,
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_shard_manifest,
            &active_validator_set,
        )
        .map_err(TransactionError::Invalid)?;
        let custody_response = build_bulletin_custody_response(
            &bundle.bulletin_commitment,
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_shard_manifest,
            &custody_assignment,
            &bundle.bulletin_custody_receipt,
            &bundle.bulletin_entries,
        )
        .map_err(TransactionError::Invalid)?;
        validate_bulletin_custody_response(
            &custody_response,
            &bundle.bulletin_commitment,
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_shard_manifest,
            &custody_assignment,
            &bundle.bulletin_custody_receipt,
            &bundle.bulletin_entries,
        )
        .map_err(TransactionError::Invalid)?;
        let reconstruction_certificate = build_bulletin_reconstruction_certificate(
            bulletin_close,
            &bundle.bulletin_commitment,
            &bundle.bulletin_availability_certificate,
            &bundle.bulletin_retrievability_profile,
            &bundle.bulletin_shard_manifest,
            &custody_assignment,
            &bundle.bulletin_custody_receipt,
            &custody_response,
            &bundle.bulletin_entries,
            &bundle.canonical_order_certificate,
            &active_validator_set,
        )
        .map_err(TransactionError::Invalid)?;

        state.insert(
            &aft_bulletin_commitment_key(bundle.bulletin_commitment.height),
            &codec::to_bytes_canonical(&bundle.bulletin_commitment)
                .map_err(TransactionError::Serialization)?,
        )?;
        for entry in &bundle.bulletin_entries {
            state.insert(
                &aft_bulletin_entry_key(entry.height, &entry.tx_hash),
                &codec::to_bytes_canonical(entry).map_err(TransactionError::Serialization)?,
            )?;
        }
        if !bundle
            .canonical_order_certificate
            .omission_proofs
            .is_empty()
        {
            for omission in &bundle.canonical_order_certificate.omission_proofs {
                if omission.offender_account_id == AccountId::default() {
                    return Err(TransactionError::Invalid(
                        "aft omission proof requires a non-zero accountable offender".into(),
                    ));
                }
                state.insert(
                    &aft_omission_proof_key(
                        bundle.canonical_order_certificate.height,
                        &omission.tx_hash,
                    ),
                    &codec::to_bytes_canonical(omission)
                        .map_err(TransactionError::Serialization)?,
                )?;
                let report = Self::omission_failure_report(omission)?;
                Self::apply_accountable_fault_report(
                    state,
                    report,
                    ctx.block_height,
                    self.config.apply_accountable_membership_updates,
                )?;
            }
            let abort = Self::build_canonical_order_abort(
                bundle.canonical_order_certificate.height,
                CanonicalOrderAbortReason::OmissionDominated,
                "objective omission proofs dominate the candidate canonical order",
                Some(&bundle.canonical_order_certificate),
                Some(bulletin_close),
            );
            Self::materialize_canonical_order_abort(state, abort)?;
            return Ok(());
        }
        state.insert(
            &aft_bulletin_availability_certificate_key(
                bundle.bulletin_availability_certificate.height,
            ),
            &codec::to_bytes_canonical(&bundle.bulletin_availability_certificate)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_bulletin_retrievability_profile_key(bundle.bulletin_retrievability_profile.height),
            &codec::to_bytes_canonical(&bundle.bulletin_retrievability_profile)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_bulletin_shard_manifest_key(bundle.bulletin_shard_manifest.height),
            &codec::to_bytes_canonical(&bundle.bulletin_shard_manifest)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_bulletin_custody_assignment_key(custody_assignment.height),
            &codec::to_bytes_canonical(&custody_assignment)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_bulletin_custody_receipt_key(bundle.bulletin_custody_receipt.height),
            &codec::to_bytes_canonical(&bundle.bulletin_custody_receipt)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_bulletin_custody_response_key(custody_response.height),
            &codec::to_bytes_canonical(&custody_response)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_order_certificate_key(bundle.canonical_order_certificate.height),
            &codec::to_bytes_canonical(&bundle.canonical_order_certificate)
                .map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_canonical_bulletin_close_key(bundle.canonical_order_certificate.height),
            &codec::to_bytes_canonical(bulletin_close).map_err(TransactionError::Serialization)?,
        )?;
        state.insert(
            &aft_bulletin_reconstruction_certificate_key(bundle.canonical_order_certificate.height),
            &codec::to_bytes_canonical(&reconstruction_certificate)
                .map_err(TransactionError::Serialization)?,
        )?;
        Ok(())
    }

    pub(super) fn materialize_bulletin_retrievability_challenge(
        state: &mut dyn StateAccess,
        challenge: &BulletinRetrievabilityChallenge,
    ) -> Result<(), TransactionError> {
        if let Some(existing) =
            Self::load_bulletin_retrievability_challenge(state, challenge.height)?
        {
            if existing != *challenge {
                return Err(TransactionError::Invalid(
                    "conflicting bulletin retrievability challenge already published for slot"
                        .into(),
                ));
            }
            return Ok(());
        }
        if Self::load_canonical_bulletin_close(state, challenge.height)?.is_some() {
            return Err(TransactionError::Invalid(
                "cannot publish bulletin retrievability challenge after canonical bulletin close publication"
                    .into(),
            ));
        }
        state.insert(
            &aft_bulletin_retrievability_challenge_key(challenge.height),
            &codec::to_bytes_canonical(challenge).map_err(TransactionError::Serialization)?,
        )?;
        if Self::load_canonical_order_abort(state, challenge.height)?.is_none() {
            let certificate = Self::load_canonical_order_certificate(state, challenge.height)?;
            let abort = Self::build_canonical_order_abort(
                challenge.height,
                CanonicalOrderAbortReason::RetrievabilityChallengeDominated,
                format!(
                    "endogenous bulletin retrievability challenge {:?}: {}",
                    challenge.kind, challenge.details
                ),
                certificate.as_ref(),
                None,
            );
            Self::materialize_canonical_order_abort(state, abort)?;
        }
        let canonical_abort = Self::load_canonical_order_abort(state, challenge.height)?
            .ok_or_else(|| {
                TransactionError::Invalid(
                    "bulletin reconstruction abort requires canonical-order abort materialization"
                        .into(),
                )
            })?;
        let reconstruction_abort = build_bulletin_reconstruction_abort(challenge, &canonical_abort)
            .map_err(TransactionError::Invalid)?;
        if let Some(existing) = Self::load_bulletin_reconstruction_abort(state, challenge.height)? {
            if existing != reconstruction_abort {
                return Err(TransactionError::Invalid(
                    "conflicting bulletin reconstruction abort already published for slot".into(),
                ));
            }
            return Ok(());
        }
        state.insert(
            &aft_bulletin_reconstruction_abort_key(challenge.height),
            &codec::to_bytes_canonical(&reconstruction_abort)
                .map_err(TransactionError::Serialization)?,
        )?;
        Ok(())
    }

    pub(super) fn materialize_recovery_impossible_abort_if_needed(
        state: &mut dyn StateAccess,
        height: u64,
    ) -> Result<(), TransactionError> {
        if Self::load_canonical_bulletin_close(state, height)
            .map_err(TransactionError::State)?
            .is_some()
            || Self::load_canonical_order_abort(state, height)
                .map_err(TransactionError::State)?
                .is_some()
        {
            return Ok(());
        }

        let Some(capsule) =
            Self::load_recovery_capsule(state, height).map_err(TransactionError::State)?
        else {
            return Ok(());
        };
        let certificates = Self::load_recovery_witness_certificates(state, height)
            .map_err(TransactionError::State)?;
        if certificates.is_empty() {
            return Ok(());
        }
        let expected_witness_manifest_hashes = certificates
            .iter()
            .map(|certificate| certificate.witness_manifest_hash)
            .collect::<Vec<_>>();
        match Self::load_recovery_threshold_status(
            state,
            height,
            &expected_witness_manifest_hashes,
            capsule.coding.recovery_threshold,
        )
        .map_err(TransactionError::State)?
        {
            RecoveryThresholdStatus::Impossible => {
                let abort = Self::build_canonical_order_abort(
                    height,
                    CanonicalOrderAbortReason::RecoveryThresholdImpossible,
                    "published recovery receipts and missingness make threshold reconstruction impossible",
                    None,
                    None,
                );
                Self::materialize_canonical_order_abort(state, abort)
            }
            RecoveryThresholdStatus::Pending | RecoveryThresholdStatus::Recoverable(_) => Ok(()),
        }
    }

    pub(super) fn recovered_publication_bundle_conflicts(
        existing: &RecoveredPublicationBundle,
        candidate: &RecoveredPublicationBundle,
    ) -> bool {
        existing.height == candidate.height
            && (existing.block_commitment_hash != candidate.block_commitment_hash
                || existing.recoverable_slot_payload_hash
                    != candidate.recoverable_slot_payload_hash
                || existing.canonical_order_publication_bundle_hash
                    != candidate.canonical_order_publication_bundle_hash
                || existing.canonical_bulletin_close_hash
                    != candidate.canonical_bulletin_close_hash)
    }

    pub(super) fn refresh_observer_challenge_surface(
        state: &mut dyn StateAccess,
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<(), TransactionError> {
        let challenges = Self::load_observer_challenges(
            state,
            challenge.epoch,
            challenge.height,
            challenge.view,
        )
        .map_err(TransactionError::State)?;
        let challenges_root = canonical_asymptote_observer_challenges_hash(&challenges)
            .map_err(TransactionError::Invalid)?;
        let challenge_count = u16::try_from(challenges.len()).map_err(|_| {
            TransactionError::Invalid("observer challenge count exceeds u16".into())
        })?;
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: challenge.epoch,
            height: challenge.height,
            view: challenge.view,
            challenges_root,
            challenge_count,
        };
        state.insert(
            &guardian_registry_observer_challenge_commitment_key(
                challenge.epoch,
                challenge.height,
                challenge.view,
            ),
            &codec::to_bytes_canonical(&challenge_commitment)
                .map_err(TransactionError::Serialization)?,
        )?;

        let abort_basis = challenge
            .canonical_close
            .clone()
            .map(|close| {
                (
                    close.assignments_hash,
                    close.transcripts_root,
                    close.transcript_count,
                    close.challenge_cutoff_timestamp_ms,
                )
            })
            .or_else(|| {
                Self::load_asymptote_observer_canonical_close(
                    state,
                    challenge.epoch,
                    challenge.height,
                    challenge.view,
                )
                .ok()
                .flatten()
                .map(|close| {
                    (
                        close.assignments_hash,
                        close.transcripts_root,
                        close.transcript_count,
                        close.challenge_cutoff_timestamp_ms,
                    )
                })
            })
            .or_else(|| {
                Self::load_asymptote_observer_canonical_abort(
                    state,
                    challenge.epoch,
                    challenge.height,
                    challenge.view,
                )
                .ok()
                .flatten()
                .map(|abort| {
                    (
                        abort.assignments_hash,
                        abort.transcripts_root,
                        abort.transcript_count,
                        abort.challenge_cutoff_timestamp_ms,
                    )
                })
            });

        if let Some((
            assignments_hash,
            transcripts_root,
            transcript_count,
            challenge_cutoff_timestamp_ms,
        )) = abort_basis
        {
            Self::materialize_observer_abort(
                state,
                AsymptoteObserverCanonicalAbort {
                    epoch: challenge.epoch,
                    height: challenge.height,
                    view: challenge.view,
                    assignments_hash,
                    transcripts_root,
                    challenges_root,
                    transcript_count,
                    challenge_count,
                    challenge_cutoff_timestamp_ms,
                },
            )?;
        }

        Ok(())
    }

    pub(super) fn observation_request_producer_account(
        challenge: &AsymptoteObserverChallenge,
    ) -> Option<AccountId> {
        challenge
            .assignment
            .as_ref()
            .map(|assignment| assignment.producer_account_id)
            .or_else(|| {
                challenge
                    .observation_request
                    .as_ref()
                    .map(|request| request.assignment.producer_account_id)
            })
            .or_else(|| {
                challenge
                    .transcript
                    .as_ref()
                    .map(|transcript| transcript.statement.assignment.producer_account_id)
            })
    }

    pub(super) fn observation_request_observer_account(
        challenge: &AsymptoteObserverChallenge,
    ) -> Option<AccountId> {
        challenge
            .assignment
            .as_ref()
            .map(|assignment| assignment.observer_account_id)
            .or_else(|| {
                challenge
                    .observation_request
                    .as_ref()
                    .map(|request| request.assignment.observer_account_id)
            })
            .or_else(|| {
                challenge
                    .transcript
                    .as_ref()
                    .map(|transcript| transcript.statement.assignment.observer_account_id)
            })
    }

    pub(super) fn accountable_challenge_offender(
        challenge: &AsymptoteObserverChallenge,
    ) -> Option<AccountId> {
        match challenge.kind {
            AsymptoteObserverChallengeKind::MissingTranscript
            | AsymptoteObserverChallengeKind::ConflictingTranscript => {
                Self::observation_request_observer_account(challenge)
            }
            AsymptoteObserverChallengeKind::TranscriptMismatch
            | AsymptoteObserverChallengeKind::VetoTranscriptPresent => {
                Self::observation_request_producer_account(challenge)
            }
            AsymptoteObserverChallengeKind::InvalidCanonicalClose => {
                Self::observation_request_producer_account(challenge)
                    .or_else(|| Some(challenge.challenger_account_id))
            }
        }
    }

    pub(super) fn omission_failure_report(
        omission: &OmissionProof,
    ) -> Result<FailureReport, TransactionError> {
        let proof = codec::to_bytes_canonical(omission).map_err(TransactionError::Serialization)?;
        Ok(FailureReport {
            offender: omission.offender_account_id,
            offense_type: OffenseType::AftOrderingOmission,
            facts: OffenseFacts::AftOrderingOmission {
                height: omission.height,
                tx_hash: omission.tx_hash,
                bulletin_root: omission.bulletin_root,
            },
            proof,
        })
    }

    pub(super) fn observer_challenge_failure_report(
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<Option<FailureReport>, TransactionError> {
        let Some(offender) = Self::accountable_challenge_offender(challenge) else {
            return Ok(None);
        };
        let proof =
            codec::to_bytes_canonical(challenge).map_err(TransactionError::Serialization)?;
        Ok(Some(FailureReport {
            offender,
            offense_type: OffenseType::AftObserverChallenge,
            facts: OffenseFacts::AftObserverChallenge {
                challenge_id: challenge.challenge_id,
                epoch: challenge.epoch,
                height: challenge.height,
                view: challenge.view,
                kind: challenge.kind,
                evidence_hash: challenge.evidence_hash,
            },
            proof,
        }))
    }

    pub(super) fn validate_observer_challenge_shape(
        challenge: &AsymptoteObserverChallenge,
    ) -> Result<(), TransactionError> {
        match challenge.kind {
            AsymptoteObserverChallengeKind::MissingTranscript => {
                let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "missing-transcript challenge must carry an assignment".into(),
                    )
                })?;
                if challenge.observation_request.is_some()
                    || challenge.transcript.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "missing-transcript challenge may only carry assignment evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_assignment_hash(assignment)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "missing-transcript challenge evidence hash does not match the assignment"
                            .into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::TranscriptMismatch => {
                let request = challenge.observation_request.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "transcript-mismatch challenge must carry an observation request".into(),
                    )
                })?;
                if challenge.assignment.is_none()
                    || challenge.transcript.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "transcript-mismatch challenge must carry only assignment and observation-request evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_observation_request_hash(request)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "transcript-mismatch challenge evidence hash does not match the offending request".into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::VetoTranscriptPresent
            | AsymptoteObserverChallengeKind::ConflictingTranscript => {
                let transcript = challenge.transcript.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "transcript-based observer challenge must carry a transcript".into(),
                    )
                })?;
                if challenge.assignment.is_none()
                    || challenge.observation_request.is_some()
                    || challenge.canonical_close.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "transcript-based observer challenge must carry only assignment and transcript evidence".into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_transcript_hash(transcript)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "observer challenge evidence hash does not match the offending transcript"
                            .into(),
                    ));
                }
            }
            AsymptoteObserverChallengeKind::InvalidCanonicalClose => {
                let close = challenge.canonical_close.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "invalid-canonical-close challenge must carry the offending canonical close"
                            .into(),
                    )
                })?;
                if challenge.assignment.is_some()
                    || challenge.observation_request.is_some()
                    || challenge.transcript.is_some()
                {
                    return Err(TransactionError::Invalid(
                        "invalid-canonical-close challenge may only carry canonical-close evidence"
                            .into(),
                    ));
                }
                let expected_hash = canonical_asymptote_observer_canonical_close_hash(close)
                    .map_err(TransactionError::Invalid)?;
                if challenge.evidence_hash != expected_hash {
                    return Err(TransactionError::Invalid(
                        "invalid-canonical-close challenge evidence hash does not match the offending close".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn apply_accountable_membership_updates(
        state: &mut dyn StateAccess,
        offender: AccountId,
        block_height: u64,
    ) -> Result<(), TransactionError> {
        let Some(validator_set_bytes) = state.get(VALIDATOR_SET_KEY)? else {
            return Ok(());
        };
        let mut sets =
            read_validator_sets(&validator_set_bytes).map_err(TransactionError::State)?;
        let active_set = effective_set_for_height(&sets, block_height).clone();

        let active_accounts = active_set
            .validators
            .iter()
            .map(|validator| validator.account_id)
            .collect::<Vec<_>>();

        let mut quarantined = Self::load_quarantined_validators(state)?;
        if active_accounts.contains(&offender) && !quarantined.contains(&offender) {
            let live_after = active_accounts
                .len()
                .saturating_sub(quarantined.len())
                .saturating_sub(1);
            if live_after >= 2 {
                quarantined.insert(offender);
                state.insert(
                    QUARANTINED_VALIDATORS_KEY,
                    &codec::to_bytes_canonical(&quarantined)
                        .map_err(TransactionError::Serialization)?,
                )?;
            }
        }

        let mut staged_next = match sets.next.clone() {
            Some(next) if next.effective_from_height > block_height => next,
            _ => {
                let mut next = active_set.clone();
                next.effective_from_height = block_height.saturating_add(1);
                next
            }
        };
        if staged_next.validators.len() <= 1 {
            return Ok(());
        }

        let original_len = staged_next.validators.len();
        staged_next
            .validators
            .retain(|validator| validator.account_id != offender);
        if staged_next.validators.len() == original_len {
            return Ok(());
        }

        staged_next.total_weight = staged_next
            .validators
            .iter()
            .map(|validator| validator.weight)
            .sum();
        sets.next = Some(staged_next);
        state.insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&sets).map_err(TransactionError::State)?,
        )?;
        Ok(())
    }

    pub(super) fn apply_accountable_fault_report(
        state: &mut dyn StateAccess,
        report: FailureReport,
        block_height: u64,
        apply_membership_updates: bool,
    ) -> Result<(), TransactionError> {
        let evidence_key =
            evidence_id(&report).map_err(|error| TransactionError::Invalid(error.to_string()))?;
        let mut evidence_registry = Self::load_evidence_registry(state)?;
        if !evidence_registry.insert(evidence_key) {
            return Ok(());
        }

        state.insert(
            EVIDENCE_REGISTRY_KEY,
            &codec::to_bytes_canonical(&evidence_registry)
                .map_err(TransactionError::Serialization)?,
        )?;
        if !apply_membership_updates {
            return Ok(());
        }
        if let Err(error) =
            Self::apply_accountable_membership_updates(state, report.offender, block_height)
        {
            warn!(
                offender = ?report.offender,
                block_height,
                error = %error,
                "accountable membership updates failed after evidence publication; leaving negative object decisive"
            );
        }
        Ok(())
    }
}
