/// Validates objective fail-closed evidence over the endogenous bulletin retrievability surface.
#[allow(clippy::too_many_arguments)]
pub fn validate_bulletin_retrievability_challenge(
    challenge: &BulletinRetrievabilityChallenge,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    profile: Option<&BulletinRetrievabilityProfile>,
    manifest: Option<&BulletinShardManifest>,
    validator_set: Option<&ValidatorSetV1>,
    assignment: Option<&BulletinCustodyAssignment>,
    receipt: Option<&BulletinCustodyReceipt>,
    response: Option<&BulletinCustodyResponse>,
    entries: &[BulletinSurfaceEntry],
) -> Result<(), String> {
    if challenge.height != bulletin_commitment.height
        || challenge.height != bulletin_availability_certificate.height
    {
        return Err(
            "bulletin retrievability challenge height does not match the slot surface".into(),
        );
    }
    let expected_commitment_hash = canonical_bulletin_commitment_hash(bulletin_commitment)?;
    if challenge.bulletin_commitment_hash != expected_commitment_hash {
        return Err(
            "bulletin retrievability challenge does not match the bulletin commitment hash".into(),
        );
    }
    let expected_availability_hash =
        canonical_bulletin_availability_certificate_hash(bulletin_availability_certificate)?;
    if challenge.bulletin_availability_certificate_hash != expected_availability_hash {
        return Err(
            "bulletin retrievability challenge does not match the bulletin availability certificate hash"
                .into(),
        );
    }
    match challenge.kind {
        BulletinRetrievabilityChallengeKind::MissingRetrievabilityProfile => {
            if profile.is_some() {
                return Err(
                    "missing retrievability profile challenge requires the profile to be absent"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash != [0u8; 32]
                || challenge.bulletin_shard_manifest_hash != [0u8; 32]
                || challenge.bulletin_custody_assignment_hash != [0u8; 32]
                || challenge.bulletin_custody_receipt_hash != [0u8; 32]
                || challenge.bulletin_custody_response_hash != [0u8; 32]
            {
                return Err(
                    "missing retrievability profile challenge must zero subordinate hashes".into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::MissingShardManifest => {
            let profile = profile.ok_or_else(|| {
                "missing shard manifest challenge requires the retrievability profile".to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            if manifest.is_some() || receipt.is_some() {
                return Err(
                    "missing shard manifest challenge requires the manifest and receipt to be absent"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
            {
                return Err(
                    "missing shard manifest challenge does not match the profile hash".into(),
                );
            }
            if challenge.bulletin_shard_manifest_hash != [0u8; 32]
                || challenge.bulletin_custody_assignment_hash != [0u8; 32]
                || challenge.bulletin_custody_receipt_hash != [0u8; 32]
                || challenge.bulletin_custody_response_hash != [0u8; 32]
            {
                return Err(
                    "missing shard manifest challenge must zero absent manifest and subordinate custody hashes"
                        .into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::ContradictoryShardManifest => {
            let profile = profile.ok_or_else(|| {
                "contradictory shard manifest challenge requires the retrievability profile"
                    .to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "contradictory shard manifest challenge requires the shard manifest".to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            if validate_bulletin_shard_manifest(
                manifest,
                bulletin_commitment,
                bulletin_availability_certificate,
                profile,
                entries,
            )
            .is_ok()
            {
                return Err(
                    "contradictory shard manifest challenge requires the published manifest to fail validation"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
            {
                return Err(
                    "contradictory shard manifest challenge does not match the profile / manifest hashes"
                        .into(),
                );
            }
            let expected_assignment_hash = match assignment {
                Some(assignment) => canonical_bulletin_custody_assignment_hash(assignment)?,
                None => [0u8; 32],
            };
            let expected_receipt_hash = match receipt {
                Some(receipt) => canonical_bulletin_custody_receipt_hash(receipt)?,
                None => [0u8; 32],
            };
            let expected_response_hash = match response {
                Some(response) => canonical_bulletin_custody_response_hash(response)?,
                None => [0u8; 32],
            };
            if challenge.bulletin_custody_assignment_hash != expected_assignment_hash
                || challenge.bulletin_custody_receipt_hash != expected_receipt_hash
                || challenge.bulletin_custody_response_hash != expected_response_hash
            {
                return Err(
                    "contradictory shard manifest challenge does not match the optional custody hashes"
                        .into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::MissingCustodyAssignment => {
            let profile = profile.ok_or_else(|| {
                "missing custody assignment challenge requires the retrievability profile"
                    .to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "missing custody assignment challenge requires the shard manifest".to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            validate_bulletin_shard_manifest(
                manifest,
                bulletin_commitment,
                bulletin_availability_certificate,
                profile,
                entries,
            )?;
            if assignment.is_some() || response.is_some() {
                return Err(
                    "missing custody assignment challenge requires the assignment and response to be absent"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
            {
                return Err(
                    "missing custody assignment challenge does not match the profile / manifest hashes"
                        .into(),
                );
            }
            let expected_receipt_hash = match receipt {
                Some(receipt) => canonical_bulletin_custody_receipt_hash(receipt)?,
                None => [0u8; 32],
            };
            if challenge.bulletin_custody_assignment_hash != [0u8; 32]
                || challenge.bulletin_custody_receipt_hash != expected_receipt_hash
                || challenge.bulletin_custody_response_hash != [0u8; 32]
            {
                return Err(
                    "missing custody assignment challenge does not match the optional receipt / response hashes"
                        .into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::ContradictoryCustodyAssignment => {
            let profile = profile.ok_or_else(|| {
                "contradictory custody assignment challenge requires the retrievability profile"
                    .to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "contradictory custody assignment challenge requires the shard manifest".to_string()
            })?;
            let validator_set = validator_set.ok_or_else(|| {
                "contradictory custody assignment challenge requires the effective validator set"
                    .to_string()
            })?;
            let assignment = assignment.ok_or_else(|| {
                "contradictory custody assignment challenge requires the custody assignment"
                    .to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            validate_bulletin_shard_manifest(
                manifest,
                bulletin_commitment,
                bulletin_availability_certificate,
                profile,
                entries,
            )?;
            if validate_bulletin_custody_assignment(assignment, profile, manifest, validator_set)
                .is_ok()
            {
                return Err(
                    "contradictory custody assignment challenge requires the published assignment to fail validation"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
                || challenge.bulletin_custody_assignment_hash
                    != canonical_bulletin_custody_assignment_hash(assignment)?
            {
                return Err(
                    "contradictory custody assignment challenge does not match the governing profile / manifest / assignment hashes"
                        .into(),
                );
            }
            let expected_receipt_hash = match receipt {
                Some(receipt) => canonical_bulletin_custody_receipt_hash(receipt)?,
                None => [0u8; 32],
            };
            let expected_response_hash = match response {
                Some(response) => canonical_bulletin_custody_response_hash(response)?,
                None => [0u8; 32],
            };
            if challenge.bulletin_custody_receipt_hash != expected_receipt_hash
                || challenge.bulletin_custody_response_hash != expected_response_hash
            {
                return Err(
                    "contradictory custody assignment challenge does not match the optional receipt / response hashes"
                        .into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::MissingCustodyReceipt => {
            let profile = profile.ok_or_else(|| {
                "missing custody receipt challenge requires the retrievability profile".to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "missing custody receipt challenge requires the shard manifest".to_string()
            })?;
            let validator_set = validator_set.ok_or_else(|| {
                "missing custody receipt challenge requires the effective validator set".to_string()
            })?;
            let assignment = assignment.ok_or_else(|| {
                "missing custody receipt challenge requires the custody assignment".to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            validate_bulletin_shard_manifest(
                manifest,
                bulletin_commitment,
                bulletin_availability_certificate,
                profile,
                entries,
            )?;
            validate_bulletin_custody_assignment(assignment, profile, manifest, validator_set)?;
            if receipt.is_some() || response.is_some() {
                return Err(
                    "missing custody receipt challenge requires the custody receipt and response to be absent"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
                || challenge.bulletin_custody_assignment_hash
                    != canonical_bulletin_custody_assignment_hash(assignment)?
            {
                return Err(
                    "missing custody receipt challenge does not match the profile / manifest / assignment hashes"
                        .into(),
                );
            }
            if challenge.bulletin_custody_receipt_hash != [0u8; 32]
                || challenge.bulletin_custody_response_hash != [0u8; 32]
            {
                return Err(
                    "missing custody receipt challenge must zero the absent receipt / response hashes".into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::ContradictoryCustodyReceipt => {
            let profile = profile.ok_or_else(|| {
                "contradictory custody receipt challenge requires the retrievability profile"
                    .to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "contradictory custody receipt challenge requires the shard manifest".to_string()
            })?;
            let validator_set = validator_set.ok_or_else(|| {
                "contradictory custody receipt challenge requires the effective validator set"
                    .to_string()
            })?;
            let assignment = assignment.ok_or_else(|| {
                "contradictory custody receipt challenge requires the custody assignment"
                    .to_string()
            })?;
            let receipt = receipt.ok_or_else(|| {
                "contradictory custody receipt challenge requires the custody receipt".to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            validate_bulletin_shard_manifest(
                manifest,
                bulletin_commitment,
                bulletin_availability_certificate,
                profile,
                entries,
            )?;
            validate_bulletin_custody_assignment(assignment, profile, manifest, validator_set)?;
            if validate_bulletin_custody_receipt(receipt, profile, manifest).is_ok() {
                return Err(
                    "contradictory custody receipt challenge requires the published receipt to fail validation"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
                || challenge.bulletin_custody_assignment_hash
                    != canonical_bulletin_custody_assignment_hash(assignment)?
                || challenge.bulletin_custody_receipt_hash
                    != canonical_bulletin_custody_receipt_hash(receipt)?
            {
                return Err(
                    "contradictory custody receipt challenge does not match the governing retrievability object hashes"
                        .into(),
                );
            }
            let expected_response_hash = match response {
                Some(response) => canonical_bulletin_custody_response_hash(response)?,
                None => [0u8; 32],
            };
            if challenge.bulletin_custody_response_hash != expected_response_hash {
                return Err(
                    "contradictory custody receipt challenge does not match the optional custody response hash"
                        .into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::MissingCustodyResponse => {
            let profile = profile.ok_or_else(|| {
                "missing custody response challenge requires the retrievability profile"
                    .to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "missing custody response challenge requires the shard manifest".to_string()
            })?;
            let validator_set = validator_set.ok_or_else(|| {
                "missing custody response challenge requires the effective validator set"
                    .to_string()
            })?;
            let assignment = assignment.ok_or_else(|| {
                "missing custody response challenge requires the custody assignment".to_string()
            })?;
            let receipt = receipt.ok_or_else(|| {
                "missing custody response challenge requires the custody receipt".to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            validate_bulletin_shard_manifest(
                manifest,
                bulletin_commitment,
                bulletin_availability_certificate,
                profile,
                entries,
            )?;
            validate_bulletin_custody_assignment(assignment, profile, manifest, validator_set)?;
            validate_bulletin_custody_receipt(receipt, profile, manifest)?;
            if response.is_some() {
                return Err(
                    "missing custody response challenge requires the custody response to be absent"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
                || challenge.bulletin_custody_assignment_hash
                    != canonical_bulletin_custody_assignment_hash(assignment)?
                || challenge.bulletin_custody_receipt_hash
                    != canonical_bulletin_custody_receipt_hash(receipt)?
            {
                return Err(
                    "missing custody response challenge does not match the governing retrievability object hashes"
                        .into(),
                );
            }
            if challenge.bulletin_custody_response_hash != [0u8; 32] {
                return Err(
                    "missing custody response challenge must zero the absent custody response hash"
                        .into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::InvalidCustodyResponse => {
            let profile = profile.ok_or_else(|| {
                "invalid custody response challenge requires the retrievability profile"
                    .to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "invalid custody response challenge requires the shard manifest".to_string()
            })?;
            let validator_set = validator_set.ok_or_else(|| {
                "invalid custody response challenge requires the effective validator set"
                    .to_string()
            })?;
            let assignment = assignment.ok_or_else(|| {
                "invalid custody response challenge requires the custody assignment".to_string()
            })?;
            let receipt = receipt.ok_or_else(|| {
                "invalid custody response challenge requires the custody receipt".to_string()
            })?;
            let response = response.ok_or_else(|| {
                "invalid custody response challenge requires the custody response".to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            validate_bulletin_shard_manifest(
                manifest,
                bulletin_commitment,
                bulletin_availability_certificate,
                profile,
                entries,
            )?;
            validate_bulletin_custody_assignment(assignment, profile, manifest, validator_set)?;
            validate_bulletin_custody_receipt(receipt, profile, manifest)?;
            if validate_bulletin_custody_response(
                response,
                bulletin_commitment,
                profile,
                manifest,
                assignment,
                receipt,
                entries,
            )
            .is_ok()
            {
                return Err(
                    "invalid custody response challenge requires the published custody response to fail validation"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
                || challenge.bulletin_custody_assignment_hash
                    != canonical_bulletin_custody_assignment_hash(assignment)?
                || challenge.bulletin_custody_receipt_hash
                    != canonical_bulletin_custody_receipt_hash(receipt)?
                || challenge.bulletin_custody_response_hash
                    != canonical_bulletin_custody_response_hash(response)?
            {
                return Err(
                    "invalid custody response challenge does not match the governing retrievability object hashes"
                        .into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::MissingSurfaceEntries => {
            let profile = profile.ok_or_else(|| {
                "missing surface entries challenge requires the retrievability profile".to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "missing surface entries challenge requires the shard manifest".to_string()
            })?;
            let validator_set = validator_set.ok_or_else(|| {
                "missing surface entries challenge requires the effective validator set"
                    .to_string()
            })?;
            let assignment = assignment.ok_or_else(|| {
                "missing surface entries challenge requires the custody assignment".to_string()
            })?;
            let receipt = receipt.ok_or_else(|| {
                "missing surface entries challenge requires the custody receipt".to_string()
            })?;
            let response = response.ok_or_else(|| {
                "missing surface entries challenge requires the custody response".to_string()
            })?;
            if !entries.is_empty() {
                return Err(
                    "missing surface entries challenge requires the bulletin entry surface to be absent"
                        .into(),
                );
            }
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            validate_bulletin_custody_assignment(assignment, profile, manifest, validator_set)?;
            validate_bulletin_custody_receipt(receipt, profile, manifest)?;
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
                || challenge.bulletin_custody_assignment_hash
                    != canonical_bulletin_custody_assignment_hash(assignment)?
                || challenge.bulletin_custody_receipt_hash
                    != canonical_bulletin_custody_receipt_hash(receipt)?
                || challenge.bulletin_custody_response_hash
                    != canonical_bulletin_custody_response_hash(response)?
            {
                return Err(
                    "missing surface entries challenge does not match the governing retrievability object hashes"
                        .into(),
                );
            }
        }
        BulletinRetrievabilityChallengeKind::InvalidSurfaceEntries => {
            let profile = profile.ok_or_else(|| {
                "invalid surface entries challenge requires the retrievability profile".to_string()
            })?;
            let manifest = manifest.ok_or_else(|| {
                "invalid surface entries challenge requires the shard manifest".to_string()
            })?;
            let validator_set = validator_set.ok_or_else(|| {
                "invalid surface entries challenge requires the effective validator set"
                    .to_string()
            })?;
            let assignment = assignment.ok_or_else(|| {
                "invalid surface entries challenge requires the custody assignment".to_string()
            })?;
            let receipt = receipt.ok_or_else(|| {
                "invalid surface entries challenge requires the custody receipt".to_string()
            })?;
            let response = response.ok_or_else(|| {
                "invalid surface entries challenge requires the custody response".to_string()
            })?;
            validate_bulletin_retrievability_profile(
                profile,
                bulletin_commitment,
                bulletin_availability_certificate,
            )?;
            validate_bulletin_custody_assignment(assignment, profile, manifest, validator_set)?;
            validate_bulletin_custody_receipt(receipt, profile, manifest)?;
            if entries.is_empty() {
                return Err(
                    "invalid surface entries challenge requires an actually published entry surface"
                        .into(),
                );
            }
            if verify_bulletin_surface_entries(challenge.height, bulletin_commitment, entries)
                .is_ok()
            {
                return Err(
                    "invalid surface entries challenge requires the published surface to fail reconstruction"
                        .into(),
                );
            }
            if challenge.bulletin_retrievability_profile_hash
                != canonical_bulletin_retrievability_profile_hash(profile)?
                || challenge.bulletin_shard_manifest_hash
                    != canonical_bulletin_shard_manifest_hash(manifest)?
                || challenge.bulletin_custody_assignment_hash
                    != canonical_bulletin_custody_assignment_hash(assignment)?
                || challenge.bulletin_custody_receipt_hash
                    != canonical_bulletin_custody_receipt_hash(receipt)?
                || challenge.bulletin_custody_response_hash
                    != canonical_bulletin_custody_response_hash(response)?
            {
                return Err(
                    "invalid surface entries challenge does not match the governing retrievability object hashes"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

/// Returns the deterministic retrievability anchor named by a canonical bulletin close, when one
/// is present.
#[allow(clippy::type_complexity)]
pub fn canonical_bulletin_close_retrievability_anchor(
    close: &CanonicalBulletinClose,
) -> Result<Option<([u8; 32], [u8; 32], [u8; 32])>, String> {
    let profile_hash = close.bulletin_retrievability_profile_hash;
    let manifest_hash = close.bulletin_shard_manifest_hash;
    let custody_hash = close.bulletin_custody_receipt_hash;
    if profile_hash == [0u8; 32] && manifest_hash == [0u8; 32] && custody_hash == [0u8; 32] {
        Ok(None)
    } else if profile_hash == [0u8; 32]
        || manifest_hash == [0u8; 32]
        || custody_hash == [0u8; 32]
    {
        Err(format!(
            "canonical bulletin close at height {} must carry either all retrievability anchor hashes or none",
            close.height
        ))
    } else {
        Ok(Some((profile_hash, manifest_hash, custody_hash)))
    }
}

/// Attaches or clears the deterministic retrievability anchor carried by a canonical bulletin
/// close.
pub fn set_canonical_bulletin_close_retrievability_anchor(
    close: &mut CanonicalBulletinClose,
    profile_hash: [u8; 32],
    manifest_hash: [u8; 32],
    custody_hash: [u8; 32],
) -> Result<(), String> {
    let all_zero =
        profile_hash == [0u8; 32] && manifest_hash == [0u8; 32] && custody_hash == [0u8; 32];
    let all_non_zero =
        profile_hash != [0u8; 32] && manifest_hash != [0u8; 32] && custody_hash != [0u8; 32];
    if !all_zero && !all_non_zero {
        return Err(format!(
            "canonical bulletin close at height {} must carry either all retrievability anchor hashes or none",
            close.height
        ));
    }
    close.bulletin_retrievability_profile_hash = profile_hash;
    close.bulletin_shard_manifest_hash = manifest_hash;
    close.bulletin_custody_receipt_hash = custody_hash;
    Ok(())
}

/// Compares canonical bulletin-close objects while ignoring only the retrievability anchor fields.
pub fn canonical_bulletin_close_eq_ignoring_retrievability_anchor(
    left: &CanonicalBulletinClose,
    right: &CanonicalBulletinClose,
) -> bool {
    left.height == right.height
        && left.cutoff_timestamp_ms == right.cutoff_timestamp_ms
        && left.bulletin_commitment_hash == right.bulletin_commitment_hash
        && left.bulletin_availability_certificate_hash == right.bulletin_availability_certificate_hash
        && left.entry_count == right.entry_count
}

/// Builds the canonical bulletin-close object for a closed bulletin surface.
pub fn build_canonical_bulletin_close(
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
) -> Result<CanonicalBulletinClose, String> {
    if bulletin_commitment.height != bulletin_availability_certificate.height {
        return Err(
            "canonical bulletin close requires same-height commitment and availability certificate"
                .into(),
        );
    }
    Ok(CanonicalBulletinClose {
        height: bulletin_commitment.height,
        cutoff_timestamp_ms: bulletin_commitment.cutoff_timestamp_ms,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(bulletin_commitment)?,
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            bulletin_availability_certificate,
        )?,
        bulletin_retrievability_profile_hash: [0u8; 32],
        bulletin_shard_manifest_hash: [0u8; 32],
        bulletin_custody_receipt_hash: [0u8; 32],
        entry_count: bulletin_commitment.entry_count,
    })
}

/// Verifies a canonical bulletin-close object against its public bulletin artifacts.
pub fn verify_canonical_bulletin_close(
    close: &CanonicalBulletinClose,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
) -> Result<(), String> {
    if close.height != bulletin_commitment.height
        || close.height != bulletin_availability_certificate.height
    {
        return Err("canonical bulletin close height does not match its public artifacts".into());
    }
    if close.cutoff_timestamp_ms != bulletin_commitment.cutoff_timestamp_ms {
        return Err(
            "canonical bulletin close cutoff does not match the bulletin commitment".into(),
        );
    }
    if close.entry_count != bulletin_commitment.entry_count {
        return Err(
            "canonical bulletin close entry count does not match the bulletin commitment".into(),
        );
    }
    let expected_commitment_hash = canonical_bulletin_commitment_hash(bulletin_commitment)?;
    if close.bulletin_commitment_hash != expected_commitment_hash {
        return Err("canonical bulletin close does not match the bulletin commitment hash".into());
    }
    let expected_availability_hash =
        canonical_bulletin_availability_certificate_hash(bulletin_availability_certificate)?;
    if close.bulletin_availability_certificate_hash != expected_availability_hash {
        return Err(
            "canonical bulletin close does not match the bulletin availability certificate hash"
                .into(),
        );
    }
    let _ = canonical_bulletin_close_retrievability_anchor(close)?;
    Ok(())
}

/// Builds the compact publication frontier carried on the live consensus path.
pub fn build_publication_frontier(
    header: &BlockHeader,
    previous: Option<&PublicationFrontier>,
) -> Result<PublicationFrontier, String> {
    let certificate = header
        .canonical_order_certificate
        .as_ref()
        .ok_or_else(|| "publication frontier requires a canonical-order certificate".to_string())?;
    let receipt = build_publication_availability_receipt(certificate)?;
    let parent_frontier_hash = previous
        .map(canonical_publication_frontier_hash)
        .transpose()?
        .unwrap_or([0u8; 32]);
    Ok(PublicationFrontier {
        height: header.height,
        view: header.view,
        counter: header.height,
        parent_frontier_hash,
        bulletin_commitment_hash: receipt.bulletin_commitment_hash,
        ordered_transactions_root_hash: receipt.ordered_transactions_root_hash,
        availability_receipt_hash: canonical_publication_availability_receipt_hash(&receipt)?,
    })
}

/// Verifies the same-slot binding between a compact publication frontier and a block header.
pub fn verify_publication_frontier_binding(
    header: &BlockHeader,
    frontier: &PublicationFrontier,
) -> Result<(), String> {
    let certificate = header.canonical_order_certificate.as_ref().ok_or_else(|| {
        "publication frontier verification requires a canonical-order certificate".to_string()
    })?;
    if frontier.height != header.height {
        return Err("publication frontier height does not match the block height".into());
    }
    if frontier.view != header.view {
        return Err("publication frontier view does not match the block view".into());
    }
    if frontier.counter != header.height {
        return Err("publication frontier counter does not match the slot height".into());
    }
    let receipt = build_publication_availability_receipt(certificate)?;
    verify_publication_availability_receipt(&receipt, certificate)?;
    if frontier.bulletin_commitment_hash != receipt.bulletin_commitment_hash {
        return Err("publication frontier does not match the bulletin commitment hash".into());
    }
    if frontier.ordered_transactions_root_hash != receipt.ordered_transactions_root_hash {
        return Err("publication frontier does not match the ordered transactions root".into());
    }
    let expected_receipt_hash = canonical_publication_availability_receipt_hash(&receipt)?;
    if frontier.availability_receipt_hash != expected_receipt_hash {
        return Err(
            "publication frontier does not match the publication availability receipt hash".into(),
        );
    }
    Ok(())
}

/// Verifies the predecessor link of a compact publication frontier.
pub fn verify_publication_frontier_chain(
    frontier: &PublicationFrontier,
    previous: &PublicationFrontier,
) -> Result<(), String> {
    if frontier.height != previous.height.saturating_add(1) {
        return Err("publication frontier height does not extend the previous frontier".into());
    }
    if frontier.counter != previous.counter.saturating_add(1) {
        return Err("publication frontier counter does not extend the previous frontier".into());
    }
    let expected_parent_hash = canonical_publication_frontier_hash(previous)?;
    if frontier.parent_frontier_hash != expected_parent_hash {
        return Err("publication frontier parent hash does not match the previous frontier".into());
    }
    Ok(())
}

/// Verifies a compact publication frontier against a block header and optional predecessor frontier.
pub fn verify_publication_frontier(
    header: &BlockHeader,
    frontier: &PublicationFrontier,
    previous: Option<&PublicationFrontier>,
) -> Result<(), String> {
    verify_publication_frontier_binding(header, frontier)?;
    match previous {
        Some(previous) => verify_publication_frontier_chain(frontier, previous),
        None if header.height <= 1 => {
            if frontier.parent_frontier_hash != [0u8; 32] {
                return Err("genesis publication frontier must have a zero parent hash".into());
            }
            Ok(())
        }
        None => Err(format!(
            "publication frontier for height {} requires a predecessor frontier",
            header.height
        )),
    }
}

/// Verifies an objective contradiction witness over compact publication frontiers.
pub fn verify_publication_frontier_contradiction(
    contradiction: &PublicationFrontierContradiction,
) -> Result<(), String> {
    if contradiction.candidate_frontier.height != contradiction.height {
        return Err("publication frontier contradiction candidate height does not match".into());
    }
    match contradiction.kind {
        PublicationFrontierContradictionKind::ConflictingFrontier => {
            if contradiction.reference_frontier.height != contradiction.height {
                return Err(
                    "publication frontier contradiction reference height does not match".into(),
                );
            }
            if contradiction.candidate_frontier.counter != contradiction.reference_frontier.counter
            {
                return Err(
                    "conflicting publication frontiers must target the same counter".into(),
                );
            }
            let candidate_hash =
                canonical_publication_frontier_hash(&contradiction.candidate_frontier)?;
            let reference_hash =
                canonical_publication_frontier_hash(&contradiction.reference_frontier)?;
            if candidate_hash == reference_hash {
                return Err(
                    "conflicting publication frontier witness must carry distinct frontiers".into(),
                );
            }
            Ok(())
        }
        PublicationFrontierContradictionKind::StaleParentLink => {
            let previous = &contradiction.reference_frontier;
            if previous.height.saturating_add(1) != contradiction.height {
                return Err(
                    "stale publication frontier witness must reference the immediately preceding frontier"
                        .into(),
                );
            }
            if contradiction.candidate_frontier.counter != contradiction.height {
                return Err(
                    "stale publication frontier witness carries an invalid slot counter".into(),
                );
            }
            let expected_parent_hash = canonical_publication_frontier_hash(previous)?;
            if contradiction.candidate_frontier.parent_frontier_hash == expected_parent_hash
                && contradiction.candidate_frontier.counter == previous.counter.saturating_add(1)
            {
                return Err(
                    "stale publication frontier witness does not contradict the predecessor link"
                        .into(),
                );
            }
            Ok(())
        }
    }
}
