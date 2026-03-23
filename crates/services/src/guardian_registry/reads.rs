use super::*;

impl GuardianRegistry {
    pub fn new(config: GuardianRegistryParams) -> Self {
        Self { config }
    }

    pub fn manifest_hash(
        manifest: &GuardianCommitteeManifest,
    ) -> Result<[u8; 32], TransactionError> {
        let bytes = codec::to_bytes_canonical(manifest).map_err(TransactionError::Serialization)?;
        sha256(&bytes)
            .map_err(|e| TransactionError::Invalid(e.to_string()))
            .and_then(|digest| {
                digest
                    .try_into()
                    .map_err(|_| TransactionError::Invalid("invalid manifest hash length".into()))
            })
    }

    pub fn load_manifest_by_hash(
        state: &dyn StateAccess,
        manifest_hash: &[u8; 32],
    ) -> Result<Option<GuardianCommitteeManifest>, StateError> {
        let key = guardian_registry_committee_key(manifest_hash);
        match state.get(&key)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_manifest_hash_by_account(
        state: &dyn StateAccess,
        account_id: &AccountId,
    ) -> Result<Option<[u8; 32]>, StateError> {
        let key = guardian_registry_committee_account_key(account_id);
        match state.get(&key)? {
            Some(bytes) => bytes
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| StateError::InvalidValue("invalid guardian manifest hash".into())),
            None => Ok(None),
        }
    }

    pub fn load_witness_manifest_by_hash(
        state: &dyn StateAccess,
        manifest_hash: &[u8; 32],
    ) -> Result<Option<GuardianWitnessCommitteeManifest>, StateError> {
        let key = guardian_registry_witness_key(manifest_hash);
        match state.get(&key)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn profile_allows_measurement(
        state: &dyn StateAccess,
        measurement_root: &[u8; 32],
    ) -> Result<bool, StateError> {
        let Some(profile_bytes) =
            state.get(&[GUARDIAN_REGISTRY_MEASUREMENT_PREFIX, b"default"].concat())?
        else {
            return Ok(false);
        };
        let profile: GuardianMeasurementProfile = codec::from_bytes_canonical(&profile_bytes)
            .map_err(|e| StateError::InvalidValue(e.to_string()))?;
        Ok(profile
            .allowed_measurement_roots
            .iter()
            .any(|root| root == measurement_root))
    }

    pub fn load_asymptote_policy(
        state: &dyn StateAccess,
        epoch: u64,
    ) -> Result<Option<AsymptotePolicy>, StateError> {
        match state.get(&guardian_registry_asymptote_policy_key(epoch))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_commitment(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinCommitment>, StateError> {
        match state.get(&aft_bulletin_commitment_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_surface_entries(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<BulletinSurfaceEntry>, StateError> {
        let prefix = [AFT_BULLETIN_ENTRY_PREFIX, &height.to_be_bytes()].concat();
        let mut entries = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let entry: BulletinSurfaceEntry = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            entries.push(entry);
        }
        entries.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));
        Ok(entries)
    }

    pub fn load_bulletin_availability_certificate(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinAvailabilityCertificate>, StateError> {
        match state.get(&aft_bulletin_availability_certificate_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_retrievability_profile(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinRetrievabilityProfile>, StateError> {
        match state.get(&aft_bulletin_retrievability_profile_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_shard_manifest(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinShardManifest>, StateError> {
        match state.get(&aft_bulletin_shard_manifest_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_custody_assignment(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinCustodyAssignment>, StateError> {
        match state.get(&aft_bulletin_custody_assignment_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_custody_receipt(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinCustodyReceipt>, StateError> {
        match state.get(&aft_bulletin_custody_receipt_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_custody_response(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinCustodyResponse>, StateError> {
        match state.get(&aft_bulletin_custody_response_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_retrievability_challenge(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinRetrievabilityChallenge>, StateError> {
        match state.get(&aft_bulletin_retrievability_challenge_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_reconstruction_certificate(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinReconstructionCertificate>, StateError> {
        match state.get(&aft_bulletin_reconstruction_certificate_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_bulletin_reconstruction_abort(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<BulletinReconstructionAbort>, StateError> {
        match state.get(&aft_bulletin_reconstruction_abort_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_canonical_bulletin_close(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalBulletinClose>, StateError> {
        match state.get(&aft_canonical_bulletin_close_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn extract_published_bulletin_surface(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<Vec<BulletinSurfaceEntry>>, StateError> {
        if let Some(challenge) = Self::load_bulletin_retrievability_challenge(state, height)? {
            return Err(StateError::InvalidValue(format!(
                "published bulletin surface at height {height} is dominated by retrievability challenge {:?}: {}",
                challenge.kind, challenge.details
            )));
        }
        let Some(bulletin_commitment) = Self::load_bulletin_commitment(state, height)? else {
            return Ok(None);
        };
        let Some(bulletin_availability_certificate) =
            Self::load_bulletin_availability_certificate(state, height)?
        else {
            return Ok(None);
        };
        let Some(bulletin_close) = Self::load_canonical_bulletin_close(state, height)? else {
            return Ok(None);
        };
        let Some(profile) = Self::load_bulletin_retrievability_profile(state, height)? else {
            return Err(StateError::InvalidValue(format!(
                "canonical bulletin close at height {height} is missing its endogenous retrievability profile"
            )));
        };
        let Some(manifest) = Self::load_bulletin_shard_manifest(state, height)? else {
            return Err(StateError::InvalidValue(format!(
                "canonical bulletin close at height {height} is missing its endogenous shard manifest"
            )));
        };
        let Some(assignment) = Self::load_bulletin_custody_assignment(state, height)? else {
            return Err(StateError::InvalidValue(format!(
                "canonical bulletin close at height {height} is missing its endogenous custody assignment"
            )));
        };
        let Some(receipt) = Self::load_bulletin_custody_receipt(state, height)? else {
            return Err(StateError::InvalidValue(format!(
                "canonical bulletin close at height {height} is missing its endogenous custody receipt"
            )));
        };
        let Some(response) = Self::load_bulletin_custody_response(state, height)? else {
            return Err(StateError::InvalidValue(format!(
                "canonical bulletin close at height {height} is missing its endogenous custody response"
            )));
        };
        let Some(reconstruction_certificate) =
            Self::load_bulletin_reconstruction_certificate(state, height)?
        else {
            return Err(StateError::InvalidValue(format!(
                "canonical bulletin close at height {height} is missing its positive bulletin reconstruction certificate"
            )));
        };
        let entries = Self::load_bulletin_surface_entries(state, height)?;
        let validator_set = Self::load_effective_validator_set_for_height(state, height)?;
        let extracted = extract_endogenous_canonical_bulletin_surface(
            &bulletin_close,
            &bulletin_commitment,
            &bulletin_availability_certificate,
            &profile,
            &manifest,
            &assignment,
            &receipt,
            &response,
            &entries,
            &validator_set,
        )
        .map_err(StateError::InvalidValue)?;
        let expected_reconstruction_certificate = build_bulletin_reconstruction_certificate(
            &bulletin_close,
            &bulletin_commitment,
            &bulletin_availability_certificate,
            &profile,
            &manifest,
            &assignment,
            &receipt,
            &response,
            &entries,
            &Self::load_canonical_order_certificate(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(format!(
                    "canonical bulletin close at height {height} is missing its canonical-order certificate"
                ))
            })?,
            &validator_set,
        )
        .map_err(StateError::InvalidValue)?;
        if reconstruction_certificate != expected_reconstruction_certificate {
            return Err(StateError::InvalidValue(format!(
                "canonical bulletin close at height {height} does not match its positive bulletin reconstruction certificate"
            )));
        }
        Ok(Some(extracted))
    }

    pub fn require_published_bulletin_surface(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<BulletinSurfaceEntry>, StateError> {
        if let Some(challenge) = Self::load_bulletin_retrievability_challenge(state, height)? {
            return Err(StateError::InvalidValue(format!(
                "published bulletin surface at height {height} is dominated by retrievability challenge {:?}: {}",
                challenge.kind, challenge.details
            )));
        }
        let bulletin_commitment =
            Self::load_bulletin_commitment(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "published bulletin commitment is required for closed-slot extraction".into(),
                )
            })?;
        let bulletin_availability_certificate =
            Self::load_bulletin_availability_certificate(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "published bulletin availability certificate is required for closed-slot extraction"
                        .into(),
                )
            })?;
        let bulletin_close =
            Self::load_canonical_bulletin_close(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "canonical bulletin close is required for closed-slot extraction".into(),
                )
            })?;
        let profile = Self::load_bulletin_retrievability_profile(state, height)?.ok_or_else(
            || {
                StateError::InvalidValue(
                    "endogenous bulletin retrievability profile is required for closed-slot extraction"
                        .into(),
                )
            },
        )?;
        let manifest = Self::load_bulletin_shard_manifest(state, height)?.ok_or_else(|| {
            StateError::InvalidValue(
                "endogenous bulletin shard manifest is required for closed-slot extraction".into(),
            )
        })?;
        let assignment =
            Self::load_bulletin_custody_assignment(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "endogenous bulletin custody assignment is required for closed-slot extraction"
                        .into(),
                )
            })?;
        let receipt = Self::load_bulletin_custody_receipt(state, height)?.ok_or_else(|| {
            StateError::InvalidValue(
                "endogenous bulletin custody receipt is required for closed-slot extraction".into(),
            )
        })?;
        let response = Self::load_bulletin_custody_response(state, height)?.ok_or_else(|| {
            StateError::InvalidValue(
                "endogenous bulletin custody response is required for closed-slot extraction"
                    .into(),
            )
        })?;
        let reconstruction_certificate =
            Self::load_bulletin_reconstruction_certificate(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "positive bulletin reconstruction certificate is required for closed-slot extraction"
                        .into(),
            )
        })?;
        let entries = Self::load_bulletin_surface_entries(state, height)?;
        let validator_set = Self::load_effective_validator_set_for_height(state, height)?;
        let extracted = extract_endogenous_canonical_bulletin_surface(
            &bulletin_close,
            &bulletin_commitment,
            &bulletin_availability_certificate,
            &profile,
            &manifest,
            &assignment,
            &receipt,
            &response,
            &entries,
            &validator_set,
        )
        .map_err(StateError::InvalidValue)?;
        let order_certificate =
            Self::load_canonical_order_certificate(state, height)?.ok_or_else(|| {
                StateError::InvalidValue(
                    "canonical-order certificate is required for closed-slot extraction".into(),
                )
            })?;
        let expected_reconstruction_certificate = build_bulletin_reconstruction_certificate(
            &bulletin_close,
            &bulletin_commitment,
            &bulletin_availability_certificate,
            &profile,
            &manifest,
            &assignment,
            &receipt,
            &response,
            &entries,
            &order_certificate,
            &validator_set,
        )
        .map_err(StateError::InvalidValue)?;
        if reconstruction_certificate != expected_reconstruction_certificate {
            return Err(StateError::InvalidValue(
                "positive bulletin reconstruction certificate does not match the canonical slot surface"
                    .into(),
            ));
        }
        Ok(extracted)
    }

    pub fn load_canonical_order_certificate(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalOrderCertificate>, StateError> {
        match state.get(&aft_order_certificate_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_canonical_order_abort(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalOrderAbort>, StateError> {
        match state.get(&aft_canonical_order_abort_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_publication_frontier(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<PublicationFrontier>, StateError> {
        match state.get(&aft_publication_frontier_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_publication_frontier_contradiction(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<PublicationFrontierContradiction>, StateError> {
        match state.get(&aft_publication_frontier_contradiction_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovery_capsule(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<RecoveryCapsule>, StateError> {
        match state.get(&aft_recovery_capsule_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovery_witness_certificate(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
    ) -> Result<Option<RecoveryWitnessCertificate>, StateError> {
        match state.get(&aft_recovery_witness_certificate_key(
            height,
            witness_manifest_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovery_witness_certificates(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<RecoveryWitnessCertificate>, StateError> {
        let prefix = [
            AFT_RECOVERY_WITNESS_CERTIFICATE_PREFIX,
            &height.to_be_bytes(),
        ]
        .concat();
        let mut certificates = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let certificate: RecoveryWitnessCertificate = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            certificates.push(certificate);
        }
        certificates.sort_unstable_by(|left, right| {
            left.witness_manifest_hash.cmp(&right.witness_manifest_hash)
        });
        Ok(certificates)
    }

    pub fn load_recovery_share_receipts(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
    ) -> Result<Vec<RecoveryShareReceipt>, StateError> {
        let prefix = aft_recovery_share_receipt_prefix(height, witness_manifest_hash);
        let mut receipts = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let receipt: RecoveryShareReceipt = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            receipts.push(receipt);
        }
        receipts.sort_unstable_by(|left, right| {
            left.block_commitment_hash.cmp(&right.block_commitment_hash)
        });
        Ok(receipts)
    }

    pub fn load_recovery_share_materials(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
    ) -> Result<Vec<RecoveryShareMaterial>, StateError> {
        let prefix = aft_recovery_share_material_prefix(height, witness_manifest_hash);
        let mut materials = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let material: RecoveryShareMaterial = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            materials.push(material);
        }
        materials.sort_unstable_by(|left, right| {
            left.block_commitment_hash.cmp(&right.block_commitment_hash)
        });
        Ok(materials)
    }

    pub fn load_recovery_share_material(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
        block_commitment_hash: &[u8; 32],
    ) -> Result<Option<RecoveryShareMaterial>, StateError> {
        match state.get(&aft_recovery_share_material_key(
            height,
            witness_manifest_hash,
            block_commitment_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovered_publication_bundles(
        state: &dyn StateAccess,
        height: u64,
        block_commitment_hash: &[u8; 32],
    ) -> Result<Vec<RecoveredPublicationBundle>, StateError> {
        let prefix = aft_recovered_publication_bundle_prefix(height, block_commitment_hash);
        let mut recovered = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let object: RecoveredPublicationBundle = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            recovered.push(object);
        }
        recovered.sort_unstable_by(|left, right| {
            left.supporting_witness_manifest_hashes
                .cmp(&right.supporting_witness_manifest_hashes)
        });
        Ok(recovered)
    }

    pub(super) fn load_recovered_publication_bundles_for_height(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Vec<RecoveredPublicationBundle>, StateError> {
        let prefix = [
            AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
            &height.to_be_bytes(),
        ]
        .concat();
        let mut recovered = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let object: RecoveredPublicationBundle = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            recovered.push(object);
        }
        recovered.sort_unstable_by(|left, right| {
            left.block_commitment_hash
                .cmp(&right.block_commitment_hash)
                .then_with(|| {
                    left.supporting_witness_manifest_hashes
                        .cmp(&right.supporting_witness_manifest_hashes)
                })
        });
        Ok(recovered)
    }
}
