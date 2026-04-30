fn canonical_omission_commitment_root(omissions: &[OmissionProof]) -> Result<[u8; 32], String> {
    let mut normalized = omissions.to_vec();
    normalized.sort_unstable_by(|left, right| {
        left.height
            .cmp(&right.height)
            .then(left.tx_hash.cmp(&right.tx_hash))
            .then(left.bulletin_root.cmp(&right.bulletin_root))
            .then(left.details.cmp(&right.details))
    });
    for window in normalized.windows(2) {
        if window[0].height == window[1].height && window[0].tx_hash == window[1].tx_hash {
            return Err(
                "canonical omission set must not contain duplicate transaction hashes".into(),
            );
        }
    }
    hash_consensus_bytes(&(
        b"aft::canonical-order::omissions::v1".as_slice(),
        &normalized,
    ))
}

fn canonical_order_score(
    randomness_beacon: &[u8; 32],
    tx_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(
        b"aft::canonical-order::rank::v1".len() + randomness_beacon.len() + tx_hash.len(),
    );
    material.extend_from_slice(b"aft::canonical-order::rank::v1");
    material.extend_from_slice(randomness_beacon);
    material.extend_from_slice(tx_hash);
    hash_consensus_bytes(&material)
}

/// Returns the deterministic canonical ordering of a bulletin-surface tx-hash set.
pub fn canonical_order_tx_hashes(
    randomness_beacon: &[u8; 32],
    tx_hashes: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, String> {
    ensure_sorted_unique_tx_hashes(tx_hashes)?;
    let mut ranked = Vec::with_capacity(tx_hashes.len());
    for tx_hash in tx_hashes {
        ranked.push((canonical_order_score(randomness_beacon, tx_hash)?, *tx_hash));
    }
    ranked.sort_unstable_by(|left, right| left.cmp(right));
    Ok(ranked.into_iter().map(|(_, tx_hash)| tx_hash).collect())
}

/// Returns the canonical ordered transaction root for an ordered transaction-hash list.
pub fn canonical_transaction_root_from_hashes(tx_hashes: &[[u8; 32]]) -> Result<Vec<u8>, String> {
    hash_consensus_bytes(&tx_hashes).map(|digest| digest.to_vec())
}

/// Returns the canonical ordered transaction root for a concrete ordered transaction list.
pub fn canonical_transactions_root(transactions: &[ChainTransaction]) -> Result<Vec<u8>, String> {
    let mut tx_hashes = Vec::with_capacity(transactions.len());
    for tx in transactions {
        tx_hashes.push(tx.hash().map_err(|e| e.to_string())?);
    }
    canonical_transaction_root_from_hashes(&tx_hashes)
}

/// Returns the sorted unique bulletin-surface entries for a candidate slot.
pub fn build_bulletin_surface_entries(
    height: u64,
    transactions: &[ChainTransaction],
) -> Result<Vec<BulletinSurfaceEntry>, String> {
    let mut tx_hashes = Vec::with_capacity(transactions.len());
    for tx in transactions {
        tx_hashes.push(tx.hash().map_err(|e| e.to_string())?);
    }
    tx_hashes.sort_unstable();
    ensure_sorted_unique_tx_hashes(&tx_hashes)?;
    Ok(tx_hashes
        .into_iter()
        .map(|tx_hash| BulletinSurfaceEntry { height, tx_hash })
        .collect())
}

/// Orders a candidate transaction batch according to the slot's canonical order rule.
pub fn canonicalize_transactions_for_header(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<Vec<ChainTransaction>, String> {
    let randomness_beacon = derive_reference_ordering_randomness_beacon(header)?;
    let mut ranked = Vec::with_capacity(transactions.len());
    for tx in transactions {
        let tx_hash = tx.hash().map_err(|e| e.to_string())?;
        ranked.push((
            canonical_order_score(&randomness_beacon, &tx_hash)?,
            tx_hash,
            tx.clone(),
        ));
    }
    ranked.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    for window in ranked.windows(2) {
        if window[0].1 == window[1].1 {
            return Err("canonical order requires unique transaction hashes per slot".into());
        }
    }
    Ok(ranked.into_iter().map(|(_, _, tx)| tx).collect())
}

/// Derives the reference public randomness beacon for a canonical order certificate.
pub fn derive_reference_ordering_randomness_beacon(
    header: &BlockHeader,
) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(
        b"aft::canonical-order::randomness::v1".len()
            + std::mem::size_of::<u64>() * 2
            + header.parent_hash.len()
            + header.producer_account_id.0.len(),
    );
    material.extend_from_slice(b"aft::canonical-order::randomness::v1");
    material.extend_from_slice(&header.height.to_be_bytes());
    material.extend_from_slice(&header.view.to_be_bytes());
    material.extend_from_slice(&header.parent_hash);
    material.extend_from_slice(&header.producer_account_id.0);
    hash_consensus_bytes(&material)
}

/// Builds the reference bulletin-board commitment for a block's admitted transaction surface.
pub fn build_reference_bulletin_commitment(
    height: u64,
    cutoff_timestamp_ms: u64,
    transactions: &[ChainTransaction],
) -> Result<BulletinCommitment, String> {
    let entries = build_bulletin_surface_entries(height, transactions)?;
    let tx_hashes: Vec<[u8; 32]> = entries.into_iter().map(|entry| entry.tx_hash).collect();
    build_bulletin_commitment_from_hashes(height, cutoff_timestamp_ms, &tx_hashes)
}

/// Returns the canonical public inputs for a block header and candidate order certificate.
pub fn canonical_order_public_inputs(
    header: &BlockHeader,
    certificate: &CanonicalOrderCertificate,
) -> Result<CanonicalOrderPublicInputs, String> {
    Ok(CanonicalOrderPublicInputs {
        height: header.height,
        parent_state_root_hash: to_root_hash(&header.parent_state_root.0)
            .map_err(|e| e.to_string())?,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(
            &certificate.bulletin_commitment,
        )?,
        randomness_beacon: certificate.randomness_beacon,
        ordered_transactions_root_hash: to_root_hash(&header.transactions_root)
            .map_err(|e| e.to_string())?,
        resulting_state_root_hash: to_root_hash(&header.state_root.0).map_err(|e| e.to_string())?,
        cutoff_timestamp_ms: certificate.bulletin_commitment.cutoff_timestamp_ms,
    })
}

/// Returns the canonical hash of a canonical-order public-input set.
pub fn canonical_order_public_inputs_hash(
    public_inputs: &CanonicalOrderPublicInputs,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(public_inputs)
}

/// Builds the reference proof bytes for a canonical order certificate.
pub fn build_reference_canonical_order_proof_bytes(
    public_inputs_hash: [u8; 32],
) -> Result<Vec<u8>, String> {
    let mut material = Vec::with_capacity(
        b"aft::canonical-order::hash-binding::v1".len() + public_inputs_hash.len(),
    );
    material.extend_from_slice(b"aft::canonical-order::hash-binding::v1");
    material.extend_from_slice(&public_inputs_hash);
    Ok(DcryptSha256::digest(&material)
        .map_err(|e| e.to_string())?
        .to_vec())
}

/// Builds the reference canonical-order certificate for a finalized block.
pub fn build_reference_canonical_order_certificate(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalOrderCertificate, String> {
    let bulletin_commitment = build_reference_bulletin_commitment(
        header.height,
        header.timestamp.saturating_mul(1000),
        transactions,
    )?;
    let ordered_transactions_root_hash =
        to_root_hash(&header.transactions_root).map_err(|e| e.to_string())?;
    let resulting_state_root_hash =
        to_root_hash(&header.state_root.0).map_err(|e| e.to_string())?;
    let randomness_beacon = derive_reference_ordering_randomness_beacon(header)?;
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin_commitment,
        &randomness_beacon,
        &ordered_transactions_root_hash,
        &resulting_state_root_hash,
    )?;

    let mut certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment,
        bulletin_availability_certificate,
        randomness_beacon,
        ordered_transactions_root_hash,
        resulting_state_root_hash,
        proof: CanonicalOrderProof::default(),
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(header, &certificate)?;
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs)?;
    certificate.proof = CanonicalOrderProof {
        proof_system: CanonicalOrderProofSystem::HashBindingV1,
        public_inputs_hash,
        proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash)?,
    };
    Ok(certificate)
}

/// Builds a succinct committed-surface canonical-order certificate for a finalized block.
pub fn build_committed_surface_canonical_order_certificate(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalOrderCertificate, String> {
    let entries = build_bulletin_surface_entries(header.height, transactions)?;
    let tx_hashes: Vec<[u8; 32]> = entries.iter().map(|entry| entry.tx_hash).collect();
    let bulletin_commitment = build_bulletin_commitment_from_hashes(
        header.height,
        header.timestamp.saturating_mul(1000),
        &tx_hashes,
    )?;
    let randomness_beacon = derive_reference_ordering_randomness_beacon(header)?;
    let expected_order = canonical_order_tx_hashes(&randomness_beacon, &tx_hashes)?;
    let expected_transactions_root = canonical_transaction_root_from_hashes(&expected_order)?;
    if header.transactions_root != expected_transactions_root {
        return Err("block transactions do not match the committed canonical order".into());
    }
    let ordered_transactions_root_hash =
        to_root_hash(&expected_transactions_root).map_err(|e| e.to_string())?;
    let resulting_state_root_hash =
        to_root_hash(&header.state_root.0).map_err(|e| e.to_string())?;
    let omission_proofs = Vec::new();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin_commitment,
        &randomness_beacon,
        &ordered_transactions_root_hash,
        &resulting_state_root_hash,
    )?;
    let proof = CommittedSurfaceCanonicalOrderProof {
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            &bulletin_availability_certificate,
        )?,
        omission_commitment_root: canonical_omission_commitment_root(&omission_proofs)?,
    };

    let mut certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment,
        bulletin_availability_certificate,
        randomness_beacon,
        ordered_transactions_root_hash,
        resulting_state_root_hash,
        proof: CanonicalOrderProof::default(),
        omission_proofs,
    };
    let public_inputs = canonical_order_public_inputs(header, &certificate)?;
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs)?;
    certificate.proof = CanonicalOrderProof {
        proof_system: CanonicalOrderProofSystem::CommittedSurfaceV1,
        public_inputs_hash,
        proof_bytes: codec::to_bytes_canonical(&proof).map_err(|e| e.to_string())?,
    };
    Ok(certificate)
}

/// Verifies a canonical order certificate against a block header and optional published bulletin.
pub fn verify_canonical_order_certificate(
    header: &BlockHeader,
    certificate: &CanonicalOrderCertificate,
    published_bulletin: Option<&BulletinCommitment>,
    published_bulletin_availability: Option<&BulletinAvailabilityCertificate>,
    published_bulletin_close: Option<&CanonicalBulletinClose>,
) -> Result<(), String> {
    if certificate.height != header.height
        || certificate.bulletin_commitment.height != header.height
        || certificate.bulletin_availability_certificate.height != header.height
    {
        return Err("canonical order certificate height does not match block height".into());
    }
    if certificate.randomness_beacon != derive_reference_ordering_randomness_beacon(header)? {
        return Err(
            "canonical order certificate randomness beacon does not match the slot schedule".into(),
        );
    }
    if let Some(published_bulletin) = published_bulletin {
        if published_bulletin != &certificate.bulletin_commitment {
            return Err(
                "canonical order certificate bulletin commitment does not match published bulletin"
                    .into(),
            );
        }
    }
    if let Some(published_bulletin_availability) = published_bulletin_availability {
        if published_bulletin_availability != &certificate.bulletin_availability_certificate {
            return Err(
                "canonical order certificate bulletin availability certificate does not match published bulletin availability"
                    .into(),
            );
        }
    }
    if let Some(published_bulletin_close) = published_bulletin_close {
        verify_canonical_bulletin_close(
            published_bulletin_close,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )?;
    }
    if !certificate.omission_proofs.is_empty() {
        return Err("canonical order certificate is dominated by objective omission proofs".into());
    }
    let public_inputs = canonical_order_public_inputs(header, certificate)?;
    if certificate.ordered_transactions_root_hash != public_inputs.ordered_transactions_root_hash {
        return Err(
            "canonical order certificate transactions root does not match block header".into(),
        );
    }
    if certificate.resulting_state_root_hash != public_inputs.resulting_state_root_hash {
        return Err(
            "canonical order certificate resulting state root does not match block header".into(),
        );
    }
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs)?;
    if certificate.proof.public_inputs_hash != public_inputs_hash {
        return Err("canonical order proof does not match canonical public inputs".into());
    }
    verify_bulletin_availability_certificate(
        &certificate.bulletin_availability_certificate,
        &certificate.bulletin_commitment,
        &certificate.randomness_beacon,
        &certificate.ordered_transactions_root_hash,
        &certificate.resulting_state_root_hash,
    )?;
    match certificate.proof.proof_system {
        CanonicalOrderProofSystem::HashBindingV1 => {
            let expected = build_reference_canonical_order_proof_bytes(public_inputs_hash)?;
            if certificate.proof.proof_bytes != expected {
                return Err("canonical order hash-binding proof bytes are invalid".into());
            }
        }
        CanonicalOrderProofSystem::CommittedSurfaceV1 => {
            let proof: CommittedSurfaceCanonicalOrderProof =
                codec::from_bytes_canonical(&certificate.proof.proof_bytes)
                    .map_err(|e| e.to_string())?;
            let availability_certificate_hash = canonical_bulletin_availability_certificate_hash(
                &certificate.bulletin_availability_certificate,
            )?;
            if availability_certificate_hash != proof.bulletin_availability_certificate_hash {
                return Err(
                    "committed-surface canonical order proof does not match the bulletin availability certificate"
                        .into(),
                );
            }
            let omission_commitment_root =
                canonical_omission_commitment_root(&certificate.omission_proofs)?;
            if omission_commitment_root != proof.omission_commitment_root {
                return Err(
                    "committed-surface canonical order proof does not match the omission commitment root"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

/// Verifies that a published bulletin surface rebuilds the specified bulletin commitment.
pub fn verify_bulletin_surface_entries(
    height: u64,
    bulletin_commitment: &BulletinCommitment,
    entries: &[BulletinSurfaceEntry],
) -> Result<(), String> {
    let entry_height = entries.first().map(|entry| entry.height).unwrap_or(height);
    if entry_height != height || entries.iter().any(|entry| entry.height != height) {
        return Err("bulletin surface entries do not match the target slot height".into());
    }
    let tx_hashes: Vec<[u8; 32]> = entries.iter().map(|entry| entry.tx_hash).collect();
    let rebuilt_commitment = build_bulletin_commitment_from_hashes(
        height,
        bulletin_commitment.cutoff_timestamp_ms,
        &tx_hashes,
    )?;
    if rebuilt_commitment != *bulletin_commitment {
        return Err("published bulletin surface does not rebuild the bulletin commitment".into());
    }
    Ok(())
}

/// Verifies that a published bulletin surface rebuilds the bulletin commitment carried by a
/// canonical-order certificate.
pub fn verify_bulletin_surface_publication(
    certificate: &CanonicalOrderCertificate,
    entries: &[BulletinSurfaceEntry],
) -> Result<(), String> {
    verify_bulletin_surface_entries(
        certificate.height,
        &certificate.bulletin_commitment,
        entries,
    )
}

/// Deterministically extracts the canonical closed bulletin surface from published artifacts.
pub fn extract_canonical_bulletin_surface(
    close: &CanonicalBulletinClose,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    entries: &[BulletinSurfaceEntry],
) -> Result<Vec<BulletinSurfaceEntry>, String> {
    verify_canonical_bulletin_close(
        close,
        bulletin_commitment,
        bulletin_availability_certificate,
    )?;
    let mut canonical_entries = entries.to_vec();
    canonical_entries.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));
    verify_bulletin_surface_entries(close.height, bulletin_commitment, &canonical_entries)?;
    let expected_entry_count = usize::try_from(close.entry_count)
        .map_err(|_| "canonical bulletin close entry count does not fit into usize".to_string())?;
    if canonical_entries.len() != expected_entry_count {
        return Err(
            "canonical bulletin close entry count does not match the published bulletin surface"
                .into(),
        );
    }
    Ok(canonical_entries)
}

/// Deterministically extracts one closed bulletin surface from endogenous protocol objects only.
pub fn extract_endogenous_canonical_bulletin_surface(
    close: &CanonicalBulletinClose,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
    assignment: &BulletinCustodyAssignment,
    receipt: &BulletinCustodyReceipt,
    response: &BulletinCustodyResponse,
    entries: &[BulletinSurfaceEntry],
    validator_set: &ValidatorSetV1,
) -> Result<Vec<BulletinSurfaceEntry>, String> {
    verify_canonical_bulletin_close(
        close,
        bulletin_commitment,
        bulletin_availability_certificate,
    )?;
    let Some((profile_hash, manifest_hash, receipt_hash)) =
        canonical_bulletin_close_retrievability_anchor(close)?
    else {
        return Err(format!(
            "canonical bulletin close at height {} does not carry an endogenous retrievability anchor",
            close.height
        ));
    };
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
    validate_bulletin_custody_response(
        response,
        bulletin_commitment,
        profile,
        manifest,
        assignment,
        receipt,
        entries,
    )?;
    let expected_profile_hash = canonical_bulletin_retrievability_profile_hash(profile)?;
    let expected_manifest_hash = canonical_bulletin_shard_manifest_hash(manifest)?;
    let expected_receipt_hash = canonical_bulletin_custody_receipt_hash(receipt)?;
    if profile_hash != expected_profile_hash
        || manifest_hash != expected_manifest_hash
        || receipt_hash != expected_receipt_hash
    {
        return Err(format!(
            "canonical bulletin close at height {} does not match the endogenous retrievability object hashes",
            close.height
        ));
    }
    extract_canonical_bulletin_surface(
        close,
        bulletin_commitment,
        bulletin_availability_certificate,
        entries,
    )
}

/// Verifies that an atomic canonical-order publication bundle is self-consistent and
/// deterministically yields one canonical bulletin-close object.
pub fn verify_canonical_order_publication_bundle(
    bundle: &CanonicalOrderPublicationBundle,
) -> Result<CanonicalBulletinClose, String> {
    if bundle.bulletin_commitment.height == 0
        || bundle.bulletin_availability_certificate.height == 0
        || bundle.canonical_order_certificate.height == 0
    {
        return Err("canonical order publication bundle requires non-zero heights".into());
    }
    if bundle.canonical_order_certificate.bulletin_commitment != bundle.bulletin_commitment {
        return Err(
            "canonical order publication bundle certificate does not match the bulletin commitment"
                .into(),
        );
    }
    if bundle
        .canonical_order_certificate
        .bulletin_availability_certificate
        != bundle.bulletin_availability_certificate
    {
        return Err(
            "canonical order publication bundle certificate does not match the bulletin availability certificate"
                .into(),
        );
    }
    validate_bulletin_retrievability_profile(
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_commitment,
        &bundle.bulletin_availability_certificate,
    )?;
    validate_bulletin_shard_manifest(
        &bundle.bulletin_shard_manifest,
        &bundle.bulletin_commitment,
        &bundle.bulletin_availability_certificate,
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_entries,
    )?;
    validate_bulletin_custody_receipt(
        &bundle.bulletin_custody_receipt,
        &bundle.bulletin_retrievability_profile,
        &bundle.bulletin_shard_manifest,
    )?;
    let mut close = build_canonical_bulletin_close(
        &bundle.bulletin_commitment,
        &bundle.bulletin_availability_certificate,
    )?;
    set_canonical_bulletin_close_retrievability_anchor(
        &mut close,
        canonical_bulletin_retrievability_profile_hash(&bundle.bulletin_retrievability_profile)?,
        canonical_bulletin_shard_manifest_hash(&bundle.bulletin_shard_manifest)?,
        canonical_bulletin_custody_receipt_hash(&bundle.bulletin_custody_receipt)?,
    )?;
    let _ = extract_canonical_bulletin_surface(
        &close,
        &bundle.bulletin_commitment,
        &bundle.bulletin_availability_certificate,
        &bundle.bulletin_entries,
    )?;
    Ok(close)
}

fn build_canonical_order_abort(
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

/// Builds the bulletin-specific reconstruction-abort object paired with a
/// retrievability-dominated canonical-order abort.
pub fn build_bulletin_reconstruction_abort(
    challenge: &BulletinRetrievabilityChallenge,
    abort: &CanonicalOrderAbort,
) -> Result<BulletinReconstructionAbort, String> {
    if challenge.height != abort.height {
        return Err(
            "bulletin reconstruction abort requires same-height challenge and canonical-order abort"
                .into(),
        );
    }
    if abort.reason != CanonicalOrderAbortReason::RetrievabilityChallengeDominated {
        return Err(
            "bulletin reconstruction abort requires a retrievability-challenge-dominated canonical-order abort"
                .into(),
        );
    }
    Ok(BulletinReconstructionAbort {
        height: challenge.height,
        kind: challenge.kind,
        bulletin_commitment_hash: challenge.bulletin_commitment_hash,
        bulletin_availability_certificate_hash: challenge.bulletin_availability_certificate_hash,
        bulletin_retrievability_profile_hash: challenge.bulletin_retrievability_profile_hash,
        bulletin_shard_manifest_hash: challenge.bulletin_shard_manifest_hash,
        bulletin_custody_receipt_hash: challenge.bulletin_custody_receipt_hash,
        bulletin_retrievability_challenge_hash:
            canonical_bulletin_retrievability_challenge_hash(challenge)?,
        canonical_order_abort_hash: canonical_order_abort_hash(abort)?,
        details: challenge.details.clone(),
    })
}

/// Builds the protocol-visible positive reconstruction outcome for one closed bulletin surface.
pub fn build_bulletin_reconstruction_certificate(
    close: &CanonicalBulletinClose,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
    assignment: &BulletinCustodyAssignment,
    receipt: &BulletinCustodyReceipt,
    response: &BulletinCustodyResponse,
    entries: &[BulletinSurfaceEntry],
    certificate: &CanonicalOrderCertificate,
    validator_set: &ValidatorSetV1,
) -> Result<BulletinReconstructionCertificate, String> {
    if certificate.height != close.height
        || certificate.height != bulletin_commitment.height
        || certificate.height != bulletin_availability_certificate.height
        || certificate.height != profile.height
        || certificate.height != manifest.height
        || certificate.height != assignment.height
        || certificate.height != receipt.height
        || certificate.height != response.height
    {
        return Err(
            "bulletin reconstruction certificate requires same-height canonical bulletin close, ordering, and retrievability objects"
                .into(),
        );
    }
    if certificate.bulletin_commitment != *bulletin_commitment {
        return Err(
            "bulletin reconstruction certificate requires the canonical-order certificate to match the bulletin commitment"
                .into(),
        );
    }
    if certificate.bulletin_availability_certificate != *bulletin_availability_certificate {
        return Err(
            "bulletin reconstruction certificate requires the canonical-order certificate to match the bulletin availability certificate"
                .into(),
        );
    }
    let reconstructed_entries = extract_endogenous_canonical_bulletin_surface(
        close,
        bulletin_commitment,
        bulletin_availability_certificate,
        profile,
        manifest,
        assignment,
        receipt,
        response,
        entries,
        validator_set,
    )?;
    Ok(BulletinReconstructionCertificate {
        height: close.height,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(bulletin_commitment)?,
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            bulletin_availability_certificate,
        )?,
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            profile,
        )?,
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(manifest)?,
        bulletin_custody_assignment_hash: canonical_bulletin_custody_assignment_hash(assignment)?,
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(receipt)?,
        bulletin_custody_response_hash: canonical_bulletin_custody_response_hash(response)?,
        canonical_bulletin_close_hash: canonical_bulletin_close_hash(close)?,
        canonical_order_certificate_hash: canonical_order_certificate_hash(certificate)?,
        reconstructed_entry_count: reconstructed_entries.len() as u32,
        reconstructed_bulletin_root: bulletin_commitment.bulletin_root,
    })
}

fn classify_canonical_order_certificate_error(error: &str) -> CanonicalOrderAbortReason {
    if error.contains("height does not match block height") {
        CanonicalOrderAbortReason::CertificateHeightMismatch
    } else if error.contains("randomness beacon does not match the slot schedule") {
        CanonicalOrderAbortReason::RandomnessMismatch
    } else if error.contains("transactions root does not match block header") {
        CanonicalOrderAbortReason::OrderedTransactionsRootMismatch
    } else if error.contains("resulting state root does not match block header") {
        CanonicalOrderAbortReason::ResultingStateRootMismatch
    } else if error.contains("proof does not match canonical public inputs") {
        CanonicalOrderAbortReason::InvalidPublicInputsHash
    } else if error.contains("recoverability root")
        || error.contains("bulletin commitment hash")
        || error.contains("published bulletin availability")
    {
        CanonicalOrderAbortReason::InvalidBulletinAvailabilityCertificate
    } else {
        CanonicalOrderAbortReason::InvalidProofBinding
    }
}

/// Deterministically derives the canonical public execution object for a committed ordering slot.
/// If the slot's proof-carried public surface is missing or invalid, returns the canonical abort
/// object that dominates the positive close path.
pub fn derive_canonical_order_execution_object(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalOrderExecutionObject, CanonicalOrderAbort> {
    let Some(certificate) = header.canonical_order_certificate.as_ref() else {
        return Err(build_canonical_order_abort(
            header.height,
            CanonicalOrderAbortReason::MissingOrderCertificate,
            "committed block does not carry a canonical-order certificate",
            None,
            None,
        ));
    };

    let bulletin_close = build_canonical_bulletin_close(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
    )
    .map_err(|error| {
        build_canonical_order_abort(
            header.height,
            CanonicalOrderAbortReason::InvalidBulletinClose,
            format!("failed to derive canonical bulletin close: {error}"),
            Some(certificate),
            None,
        )
    })?;

    if !certificate.omission_proofs.is_empty() {
        return Err(build_canonical_order_abort(
            header.height,
            CanonicalOrderAbortReason::OmissionDominated,
            "objective omission proofs dominate the candidate canonical order",
            Some(certificate),
            Some(&bulletin_close),
        ));
    }

    if let Err(error) = verify_canonical_order_certificate(
        header,
        certificate,
        Some(&certificate.bulletin_commitment),
        Some(&certificate.bulletin_availability_certificate),
        Some(&bulletin_close),
    ) {
        return Err(build_canonical_order_abort(
            header.height,
            classify_canonical_order_certificate_error(&error),
            format!("canonical-order certificate verification failed: {error}"),
            Some(certificate),
            Some(&bulletin_close),
        ));
    }

    let bulletin_entries =
        build_bulletin_surface_entries(header.height, transactions).map_err(|error| {
            build_canonical_order_abort(
                header.height,
                CanonicalOrderAbortReason::BulletinSurfaceReconstructionFailure,
                format!("failed to reconstruct canonical bulletin surface: {error}"),
                Some(certificate),
                Some(&bulletin_close),
            )
        })?;

    if let Err(error) = verify_bulletin_surface_publication(certificate, &bulletin_entries) {
        return Err(build_canonical_order_abort(
            header.height,
            CanonicalOrderAbortReason::BulletinSurfaceMismatch,
            format!("proof-carried bulletin surface is invalid: {error}"),
            Some(certificate),
            Some(&bulletin_close),
        ));
    }

    Ok(CanonicalOrderExecutionObject {
        bulletin_commitment: certificate.bulletin_commitment.clone(),
        bulletin_entries,
        bulletin_availability_certificate: certificate.bulletin_availability_certificate.clone(),
        bulletin_retrievability_profile: {
            let profile = build_bulletin_retrievability_profile(
                &certificate.bulletin_commitment,
                &certificate.bulletin_availability_certificate,
            )
            .map_err(|error| {
                build_canonical_order_abort(
                    header.height,
                    CanonicalOrderAbortReason::InvalidBulletinAvailabilityCertificate,
                    format!("failed to derive bulletin retrievability profile: {error}"),
                    Some(certificate),
                    Some(&bulletin_close),
                )
            })?;
            profile
        },
        bulletin_shard_manifest: Default::default(),
        bulletin_custody_receipt: Default::default(),
        bulletin_close,
        canonical_order_certificate: certificate.clone(),
    })
    .and_then(|mut execution_object| {
        execution_object.bulletin_shard_manifest = build_bulletin_shard_manifest(
            &execution_object.bulletin_commitment,
            &execution_object.bulletin_availability_certificate,
            &execution_object.bulletin_retrievability_profile,
            &execution_object.bulletin_entries,
        )
        .map_err(|error| {
            build_canonical_order_abort(
                header.height,
                CanonicalOrderAbortReason::BulletinSurfaceMismatch,
                format!("failed to derive bulletin shard manifest: {error}"),
                Some(certificate),
                Some(&execution_object.bulletin_close),
            )
        })?;
        execution_object.bulletin_custody_receipt = build_bulletin_custody_receipt(
            &execution_object.bulletin_retrievability_profile,
            &execution_object.bulletin_shard_manifest,
        )
        .map_err(|error| {
            build_canonical_order_abort(
                header.height,
                CanonicalOrderAbortReason::InvalidBulletinAvailabilityCertificate,
                format!("failed to derive bulletin custody receipt: {error}"),
                Some(certificate),
                Some(&execution_object.bulletin_close),
            )
        })?;
        let profile_hash = canonical_bulletin_retrievability_profile_hash(
            &execution_object.bulletin_retrievability_profile,
        )
        .map_err(|error| {
            build_canonical_order_abort(
                header.height,
                CanonicalOrderAbortReason::InvalidBulletinAvailabilityCertificate,
                format!("failed to hash bulletin retrievability profile: {error}"),
                Some(certificate),
                Some(&execution_object.bulletin_close),
            )
        })?;
        let manifest_hash =
            canonical_bulletin_shard_manifest_hash(&execution_object.bulletin_shard_manifest)
                .map_err(|error| {
                    build_canonical_order_abort(
                        header.height,
                        CanonicalOrderAbortReason::BulletinSurfaceMismatch,
                        format!("failed to hash bulletin shard manifest: {error}"),
                        Some(certificate),
                        Some(&execution_object.bulletin_close),
                    )
                })?;
        let custody_hash =
            canonical_bulletin_custody_receipt_hash(&execution_object.bulletin_custody_receipt)
                .map_err(|error| {
                    build_canonical_order_abort(
                        header.height,
                        CanonicalOrderAbortReason::InvalidBulletinAvailabilityCertificate,
                        format!("failed to hash bulletin custody receipt: {error}"),
                        Some(certificate),
                        Some(&execution_object.bulletin_close),
                    )
                })?;
        set_canonical_bulletin_close_retrievability_anchor(
            &mut execution_object.bulletin_close,
            profile_hash,
            manifest_hash,
            custody_hash,
        )
        .map_err(|error| {
            build_canonical_order_abort(
                header.height,
                CanonicalOrderAbortReason::InvalidBulletinClose,
                format!("failed to attach bulletin retrievability anchor: {error}"),
                Some(certificate),
                Some(&execution_object.bulletin_close),
            )
        })?;
        Ok(execution_object)
    })
}

/// Derives the canonical public obstruction for a committed ordering slot, if one exists.
pub fn derive_canonical_order_public_obstruction(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Option<CanonicalOrderAbort> {
    derive_canonical_order_execution_object(header, transactions).err()
}

/// Derives the sealing-side component of the protocol-wide canonical collapse object.
pub fn derive_canonical_sealing_collapse(
    proof: &SealedFinalityProof,
) -> Result<CanonicalSealingCollapse, String> {
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&proof.observer_transcripts)?;
    let challenges_root = canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)?;

    if let Some(commitment) = proof.observer_transcript_commitment.as_ref() {
        if commitment.transcripts_root != transcripts_root {
            return Err(
                "sealed finality proof transcript commitment does not match the canonical transcript surface"
                    .into(),
            );
        }
        if commitment.transcript_count != proof.observer_transcripts.len() as u16 {
            return Err(
                "sealed finality proof transcript commitment count does not match the transcript surface"
                    .into(),
            );
        }
    }
    if let Some(commitment) = proof.observer_challenge_commitment.as_ref() {
        if commitment.challenges_root != challenges_root {
            return Err(
                "sealed finality proof challenge commitment does not match the canonical challenge surface"
                    .into(),
            );
        }
        if commitment.challenge_count != proof.observer_challenges.len() as u16 {
            return Err(
                "sealed finality proof challenge commitment count does not match the challenge surface"
                    .into(),
            );
        }
    }

    match proof.collapse_state {
        CollapseState::SealedFinal => {
            if proof.finality_tier != FinalityTier::SealedFinal {
                return Err(
                    "sealed finality proof close path must carry the SealedFinal tier".into(),
                );
            }
            let close = proof.observer_canonical_close.as_ref().ok_or_else(|| {
                "sealed finality proof is missing a canonical observer close".to_string()
            })?;
            if proof.observer_canonical_abort.is_some() {
                return Err(
                    "sealed finality proof close path may not also carry a canonical observer abort"
                        .into(),
                );
            }
            if close.transcripts_root != transcripts_root
                || close.challenges_root != challenges_root
            {
                return Err(
                    "sealed finality proof close path does not match the canonical observer surface"
                        .into(),
                );
            }
            if close.transcript_count != proof.observer_transcripts.len() as u16
                || close.challenge_count != proof.observer_challenges.len() as u16
            {
                return Err(
                    "sealed finality proof close counts do not match the canonical observer surface"
                        .into(),
                );
            }
            if !proof.observer_challenges.is_empty() || close.challenge_count != 0 {
                return Err(
                    "sealed finality proof close path is challenge-dominated and therefore not decisive"
                        .into(),
                );
            }
            Ok(CanonicalSealingCollapse {
                epoch: proof.epoch,
                height: close.height,
                view: close.view,
                kind: CanonicalCollapseKind::Close,
                finality_tier: proof.finality_tier.clone(),
                collapse_state: proof.collapse_state,
                transcripts_root,
                challenges_root,
                resolution_hash: canonical_asymptote_observer_canonical_close_hash(close)?,
            })
        }
        CollapseState::Abort => {
            if proof.finality_tier != FinalityTier::BaseFinal {
                return Err(
                    "sealed finality proof abort path must carry the BaseFinal tier".into(),
                );
            }
            let abort = proof.observer_canonical_abort.as_ref().ok_or_else(|| {
                "sealed finality proof is missing a canonical observer abort".to_string()
            })?;
            if proof.observer_canonical_close.is_some() {
                return Err(
                    "sealed finality proof abort path may not also carry a canonical observer close"
                        .into(),
                );
            }
            if abort.transcripts_root != transcripts_root
                || abort.challenges_root != challenges_root
            {
                return Err(
                    "sealed finality proof abort path does not match the canonical observer surface"
                        .into(),
                );
            }
            if abort.transcript_count != proof.observer_transcripts.len() as u16
                || abort.challenge_count != proof.observer_challenges.len() as u16
            {
                return Err(
                    "sealed finality proof abort counts do not match the canonical observer surface"
                        .into(),
                );
            }
            if proof.observer_challenges.is_empty() || abort.challenge_count == 0 {
                return Err(
                    "sealed finality proof abort path must bind a non-empty canonical challenge surface"
                        .into(),
                );
            }
            Ok(CanonicalSealingCollapse {
                epoch: proof.epoch,
                height: abort.height,
                view: abort.view,
                kind: CanonicalCollapseKind::Abort,
                finality_tier: proof.finality_tier.clone(),
                collapse_state: proof.collapse_state,
                transcripts_root,
                challenges_root,
                resolution_hash: canonical_asymptote_observer_canonical_abort_hash(abort)?,
            })
        }
        state => Err(format!(
            "sealed finality proof is not in a decisive canonical collapse state: {:?}",
            state
        )),
    }
}

/// Derives the protocol-wide canonical collapse object for a committed AFT block.
pub fn derive_canonical_collapse_object(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalCollapseObject, String> {
    derive_canonical_collapse_object_with_previous(header, transactions, None)
}

/// Derives the protocol-wide canonical collapse object while binding the previous slot's
/// collapse commitment into the current slot's continuity surface.
pub fn derive_canonical_collapse_object_with_previous(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    previous: Option<&CanonicalCollapseObject>,
) -> Result<CanonicalCollapseObject, String> {
    let ordering = match derive_canonical_order_execution_object(header, transactions) {
        Ok(execution_object) => CanonicalOrderingCollapse {
            height: header.height,
            kind: CanonicalCollapseKind::Close,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &execution_object.bulletin_commitment,
            )?,
            bulletin_availability_certificate_hash:
                canonical_bulletin_availability_certificate_hash(
                    &execution_object.bulletin_availability_certificate,
                )?,
            bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
                &execution_object.bulletin_retrievability_profile,
            )?,
            bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(
                &execution_object.bulletin_shard_manifest,
            )?,
            bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(
                &execution_object.bulletin_custody_receipt,
            )?,
            bulletin_close_hash: canonical_bulletin_close_hash(&execution_object.bulletin_close)?,
            canonical_order_certificate_hash: canonical_order_certificate_hash(
                &execution_object.canonical_order_certificate,
            )?,
        },
        Err(abort) => CanonicalOrderingCollapse {
            height: abort.height,
            kind: CanonicalCollapseKind::Abort,
            bulletin_commitment_hash: abort.bulletin_commitment_hash,
            bulletin_availability_certificate_hash: abort.bulletin_availability_certificate_hash,
            bulletin_retrievability_profile_hash: [0u8; 32],
            bulletin_shard_manifest_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_close_hash: abort.bulletin_close_hash,
            canonical_order_certificate_hash: abort.canonical_order_certificate_hash,
        },
    };
    let sealing = header
        .sealed_finality_proof
        .as_ref()
        .map(derive_canonical_sealing_collapse)
        .transpose()?;
    verify_block_header_canonical_collapse_evidence(header, previous)?;

    let mut collapse = CanonicalCollapseObject {
        height: header.height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering,
        sealing,
        transactions_root_hash: to_root_hash(&header.transactions_root)
            .map_err(|e| e.to_string())?,
        resulting_state_root_hash: to_root_hash(&header.state_root.0).map_err(|e| e.to_string())?,
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    bind_canonical_collapse_continuity(&mut collapse, previous)?;
    Ok(collapse)
}

/// Derives the protocol-wide canonical collapse object from a recovered full extractable
/// slot surface while binding the previous slot's continuity surface.
pub fn derive_canonical_collapse_object_from_recovered_surface(
    full_surface: &RecoverableSlotPayloadV5,
    bulletin_close: &CanonicalBulletinClose,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<CanonicalCollapseObject, String> {
    let certificate = &full_surface.canonical_order_certificate;
    let expected_bulletin_close = build_canonical_bulletin_close(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
    )?;
    if !canonical_bulletin_close_eq_ignoring_retrievability_anchor(
        &expected_bulletin_close,
        bulletin_close,
    ) {
        return Err(
            "recovered full extractable slot surface carries a bulletin close that does not match the recovered canonical order certificate".into(),
        );
    }

    let mut collapse = CanonicalCollapseObject {
        height: full_surface.height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: CanonicalOrderingCollapse {
            height: full_surface.height,
            kind: if certificate.omission_proofs.is_empty() {
                CanonicalCollapseKind::Close
            } else {
                CanonicalCollapseKind::Abort
            },
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )?,
            bulletin_availability_certificate_hash:
                canonical_bulletin_availability_certificate_hash(
                    &certificate.bulletin_availability_certificate,
                )?,
            bulletin_retrievability_profile_hash: bulletin_close
                .bulletin_retrievability_profile_hash,
            bulletin_shard_manifest_hash: bulletin_close.bulletin_shard_manifest_hash,
            bulletin_custody_receipt_hash: bulletin_close.bulletin_custody_receipt_hash,
            bulletin_close_hash: canonical_bulletin_close_hash(bulletin_close)?,
            canonical_order_certificate_hash: canonical_order_certificate_hash(certificate)?,
        },
        sealing: None,
        transactions_root_hash: certificate.ordered_transactions_root_hash,
        resulting_state_root_hash: certificate.resulting_state_root_hash,
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    bind_canonical_collapse_continuity(&mut collapse, previous)?;
    Ok(collapse)
}
