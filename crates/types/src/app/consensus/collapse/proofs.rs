/// Returns the statement hash certified by a recursive canonical-collapse proof step.
pub fn canonical_collapse_recursive_statement_hash(
    commitment: &CanonicalCollapseCommitment,
    previous_canonical_collapse_commitment_hash: [u8; 32],
    payload_hash: [u8; 32],
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(&(
        b"aft::canonical-collapse::pcd-statement::v1",
        commitment,
        previous_canonical_collapse_commitment_hash,
        payload_hash,
    ))
}

/// Returns the public inputs bound by a recursive canonical-collapse proof step.
pub fn canonical_collapse_continuity_public_inputs(
    commitment: &CanonicalCollapseCommitment,
    previous_canonical_collapse_commitment_hash: [u8; 32],
    payload_hash: [u8; 32],
    previous_recursive_proof_hash: [u8; 32],
) -> CanonicalCollapseContinuityPublicInputs {
    CanonicalCollapseContinuityPublicInputs {
        commitment: commitment.clone(),
        previous_canonical_collapse_commitment_hash,
        payload_hash,
        previous_recursive_proof_hash,
    }
}

/// Returns the mock proof bytes for the succinct recursive continuity backend.
pub fn canonical_collapse_succinct_mock_proof_bytes(
    public_inputs: &CanonicalCollapseContinuityPublicInputs,
) -> Result<Vec<u8>, String> {
    Ok(hash_consensus_bytes(&(
        b"aft::canonical-collapse::succinct-mock-proof::v1",
        public_inputs,
    ))?
    .to_vec())
}

fn canonical_collapse_continuity_proof_system_from_env() -> CanonicalCollapseContinuityProofSystem {
    match std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM") {
        Ok(value) if value.eq_ignore_ascii_case("succinct-sp1-v1") => {
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1
        }
        _ => CanonicalCollapseContinuityProofSystem::HashPcdV1,
    }
}

/// Returns the reference proof bytes for a recursive canonical-collapse proof step.
pub fn canonical_collapse_recursive_proof_bytes(
    proof_system: CanonicalCollapseContinuityProofSystem,
    statement_hash: [u8; 32],
    previous_recursive_proof_hash: [u8; 32],
    public_inputs: &CanonicalCollapseContinuityPublicInputs,
) -> Result<Vec<u8>, String> {
    match proof_system {
        CanonicalCollapseContinuityProofSystem::HashPcdV1 => Ok(hash_consensus_bytes(&(
            b"aft::canonical-collapse::pcd-proof::v1",
            proof_system as u8,
            statement_hash,
            previous_recursive_proof_hash,
        ))?
        .to_vec()),
        CanonicalCollapseContinuityProofSystem::SuccinctSp1V1 => {
            canonical_collapse_succinct_mock_proof_bytes(public_inputs)
        }
    }
}

/// Returns the canonical hash of a recursive canonical-collapse proof step.
pub fn canonical_collapse_recursive_proof_hash(
    proof: &CanonicalCollapseRecursiveProof,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(proof)
}

/// Builds the recursive proof step for a canonical collapse object.
pub fn canonical_collapse_recursive_proof(
    collapse: &CanonicalCollapseObject,
    previous: Option<&CanonicalCollapseRecursiveProof>,
) -> Result<CanonicalCollapseRecursiveProof, String> {
    let proof_system = canonical_collapse_continuity_proof_system_from_env();
    let previous_recursive_proof_hash = if collapse.height <= 1 {
        if previous.is_some() {
            return Err(format!(
                "canonical collapse proof at height {} must not carry a previous proof",
                collapse.height
            ));
        }
        [0u8; 32]
    } else {
        canonical_collapse_recursive_proof_hash(previous.ok_or_else(|| {
            format!(
                "canonical collapse proof at height {} requires a previous proof",
                collapse.height
            )
        })?)?
    };
    let commitment = canonical_collapse_commitment(collapse);
    let payload_hash = canonical_collapse_payload_hash(collapse)?;
    let statement_hash = canonical_collapse_recursive_statement_hash(
        &commitment,
        collapse.previous_canonical_collapse_commitment_hash,
        payload_hash,
    )?;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &commitment,
        collapse.previous_canonical_collapse_commitment_hash,
        payload_hash,
        previous_recursive_proof_hash,
    );
    let proof_bytes = canonical_collapse_recursive_proof_bytes(
        proof_system,
        statement_hash,
        previous_recursive_proof_hash,
        &public_inputs,
    )?;
    Ok(CanonicalCollapseRecursiveProof {
        commitment,
        previous_canonical_collapse_commitment_hash: collapse
            .previous_canonical_collapse_commitment_hash,
        payload_hash,
        proof_system,
        previous_recursive_proof_hash,
        proof_bytes,
    })
}

/// Verifies the self-contained syntax and proof bytes of a recursive canonical-collapse proof
/// step without consulting anchored predecessor state.
pub fn verify_canonical_collapse_recursive_proof(
    proof: &CanonicalCollapseRecursiveProof,
) -> Result<(), String> {
    if proof.commitment.height <= 1 {
        if proof.previous_canonical_collapse_commitment_hash != [0u8; 32] {
            return Err(format!(
                "canonical collapse proof at height {} must carry a zero predecessor commitment hash",
                proof.commitment.height
            ));
        }
    } else {
        if proof.previous_canonical_collapse_commitment_hash == [0u8; 32] {
            return Err(format!(
                "canonical collapse proof at height {} must carry a non-zero predecessor commitment hash",
                proof.commitment.height
            ));
        }
    }

    let statement_hash = canonical_collapse_recursive_statement_hash(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
    )?;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
        proof.previous_recursive_proof_hash,
    );
    let expected_proof_bytes = canonical_collapse_recursive_proof_bytes(
        proof.proof_system,
        statement_hash,
        proof.previous_recursive_proof_hash,
        &public_inputs,
    )?;
    if proof.proof_bytes != expected_proof_bytes {
        return Err(format!(
            "canonical collapse proof bytes mismatch for height {}",
            proof.commitment.height
        ));
    }
    Ok(())
}

/// Verifies that a recursive proof step matches a concrete canonical collapse object and its
/// anchored predecessor state when required.
pub fn verify_canonical_collapse_recursive_proof_matches_collapse(
    collapse: &CanonicalCollapseObject,
    proof: &CanonicalCollapseRecursiveProof,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    verify_canonical_collapse_recursive_proof(proof)?;
    if proof.commitment != canonical_collapse_commitment(collapse) {
        return Err(format!(
            "canonical collapse proof commitment mismatch for height {}",
            collapse.height
        ));
    }
    if proof.previous_canonical_collapse_commitment_hash
        != collapse.previous_canonical_collapse_commitment_hash
    {
        return Err(format!(
            "canonical collapse proof predecessor hash mismatch for height {}",
            collapse.height
        ));
    }
    let expected_payload_hash = canonical_collapse_payload_hash(collapse)?;
    if proof.payload_hash != expected_payload_hash {
        return Err(format!(
            "canonical collapse proof payload hash mismatch for height {}",
            collapse.height
        ));
    }
    if collapse.height <= 1 {
        if proof.previous_recursive_proof_hash != [0u8; 32] {
            return Err(format!(
                "canonical collapse proof at height {} must carry a zero predecessor proof hash",
                collapse.height
            ));
        }
        return Ok(());
    }
    let previous = previous.ok_or_else(|| {
        format!(
            "canonical collapse proof at height {} requires an anchored predecessor collapse object",
            collapse.height
        )
    })?;
    if previous.height + 1 != collapse.height {
        return Err(format!(
            "canonical collapse proof expected anchored predecessor height {}, found {}",
            collapse.height - 1,
            previous.height
        ));
    }
    let previous_commitment_hash =
        canonical_collapse_commitment_hash(&canonical_collapse_commitment(previous))?;
    if proof.previous_canonical_collapse_commitment_hash != previous_commitment_hash {
        return Err(format!(
            "canonical collapse proof predecessor commitment hash mismatch for height {}",
            collapse.height
        ));
    }
    let expected_accumulator = hash_consensus_bytes(&(
        b"aft::canonical-collapse::accumulator::v1",
        proof.commitment.height,
        previous.continuity_accumulator_hash,
        proof.payload_hash,
    ))?;
    if proof.commitment.continuity_accumulator_hash != expected_accumulator {
        return Err(format!(
            "canonical collapse proof continuity accumulator mismatch for height {}",
            collapse.height
        ));
    }
    let expected_previous_proof_hash =
        canonical_collapse_recursive_proof_hash(&previous.continuity_recursive_proof)?;
    if proof.previous_recursive_proof_hash != expected_previous_proof_hash {
        return Err(format!(
            "canonical collapse proof predecessor proof hash mismatch for height {}",
            collapse.height
        ));
    }
    Ok(())
}

/// Builds the live proposal-time recursive-continuity certificate for extending a predecessor
/// canonical collapse object into `covered_height`.
pub fn canonical_collapse_extension_certificate(
    covered_height: u64,
    predecessor: &CanonicalCollapseObject,
) -> Result<CanonicalCollapseExtensionCertificate, String> {
    if predecessor.height + 1 != covered_height {
        return Err(format!(
            "canonical collapse extension expected predecessor height {}, found {}",
            covered_height - 1,
            predecessor.height
        ));
    }
    verify_canonical_collapse_recursive_proof(&predecessor.continuity_recursive_proof)?;
    Ok(CanonicalCollapseExtensionCertificate {
        predecessor_commitment: canonical_collapse_commitment(predecessor),
        predecessor_recursive_proof_hash: canonical_collapse_recursive_proof_hash(
            &predecessor.continuity_recursive_proof,
        )?,
    })
}

/// Reconstructs the predecessor commitment implied by an extension certificate.
pub fn canonical_collapse_extension_predecessor_commitment(
    covered_height: u64,
    certificate: &CanonicalCollapseExtensionCertificate,
) -> Result<CanonicalCollapseCommitment, String> {
    if covered_height <= 1 {
        return Err(
            "genesis or height-1 block headers do not admit a predecessor commitment".into(),
        );
    }
    let commitment = certificate.predecessor_commitment.clone();
    if commitment.height + 1 != covered_height {
        return Err(format!(
            "canonical collapse extension expected predecessor height {}, found {}",
            covered_height - 1,
            commitment.height
        ));
    }
    Ok(commitment)
}

/// Returns the predecessor-commitment hash implied by an extension certificate.
pub fn canonical_collapse_extension_predecessor_commitment_hash(
    covered_height: u64,
    certificate: &CanonicalCollapseExtensionCertificate,
) -> Result<[u8; 32], String> {
    canonical_collapse_commitment_hash(&canonical_collapse_extension_predecessor_commitment(
        covered_height,
        certificate,
    )?)
}

/// Returns the canonical payload hash of a protocol-wide canonical collapse object, excluding the
/// recursive accumulator field.
///
/// The rolling continuity chain must stay aligned with the proof-carrying block surface even when
/// same-slot publication later enriches the object with ordering-bundle or sealing material that
/// is not guaranteed to be available at the instant successors extend the committed slot. We
/// therefore hash only the stable collapse surface that successors can safely bind through the
/// header/evidence path, rather than late materialization fields.
pub fn canonical_collapse_payload_hash(
    collapse: &CanonicalCollapseObject,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(&(
        b"aft::canonical-collapse::payload::v1",
        collapse.height,
        collapse.previous_canonical_collapse_commitment_hash,
        collapse.ordering.height,
        collapse.ordering.kind,
        collapse.ordering.bulletin_commitment_hash,
        collapse.ordering.bulletin_availability_certificate_hash,
        collapse.ordering.canonical_order_certificate_hash,
        collapse.transactions_root_hash,
        collapse.resulting_state_root_hash,
    ))
}

/// Returns the predecessor-commitment hash that a collapse object at `height` must carry.
pub fn expected_previous_canonical_collapse_commitment_hash(
    height: u64,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<[u8; 32], String> {
    if height <= 1 {
        return Ok([0u8; 32]);
    }

    let previous = previous.ok_or_else(|| {
        format!(
            "canonical collapse continuity requires a previous collapse object for height {}",
            height
        )
    })?;
    if previous.height + 1 != height {
        return Err(format!(
            "canonical collapse continuity expected previous height {}, found {}",
            height - 1,
            previous.height
        ));
    }

    canonical_collapse_commitment_hash_from_object(previous)
}

/// Returns the continuity accumulator hash that a collapse object at `height` must carry.
pub fn expected_previous_canonical_collapse_accumulator_hash(
    height: u64,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<[u8; 32], String> {
    if height <= 1 {
        return Ok([0u8; 32]);
    }

    let previous = previous.ok_or_else(|| {
        format!(
            "canonical collapse accumulator requires a previous collapse object for height {}",
            height
        )
    })?;
    if previous.height + 1 != height {
        return Err(format!(
            "canonical collapse accumulator expected previous height {}, found {}",
            height - 1,
            previous.height
        ));
    }
    Ok(previous.continuity_accumulator_hash)
}

/// Computes the rolling continuity accumulator hash for a collapse object.
pub fn canonical_collapse_continuity_accumulator_hash(
    collapse: &CanonicalCollapseObject,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<[u8; 32], String> {
    let previous_accumulator =
        expected_previous_canonical_collapse_accumulator_hash(collapse.height, previous)?;
    let payload_hash = canonical_collapse_payload_hash(collapse)?;
    hash_consensus_bytes(&(
        b"aft::canonical-collapse::accumulator::v1",
        collapse.height,
        previous_accumulator,
        payload_hash,
    ))
}

/// Canonically binds both the previous-collapse hash and rolling accumulator for a collapse object.
pub fn bind_canonical_collapse_continuity(
    collapse: &mut CanonicalCollapseObject,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    collapse.previous_canonical_collapse_commitment_hash =
        expected_previous_canonical_collapse_commitment_hash(collapse.height, previous)?;
    collapse.continuity_accumulator_hash =
        canonical_collapse_continuity_accumulator_hash(collapse, previous)?;
    collapse.continuity_recursive_proof = canonical_collapse_recursive_proof(
        collapse,
        previous.map(|item| &item.continuity_recursive_proof),
    )?;
    Ok(())
}

/// Verifies that a collapse object correctly links to the previous slot.
pub fn verify_canonical_collapse_continuity(
    collapse: &CanonicalCollapseObject,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    let expected = expected_previous_canonical_collapse_commitment_hash(collapse.height, previous)?;
    if collapse.previous_canonical_collapse_commitment_hash != expected {
        return Err(format!(
            "canonical collapse continuity commitment hash mismatch for height {}",
            collapse.height
        ));
    }
    let expected_accumulator = canonical_collapse_continuity_accumulator_hash(collapse, previous)?;
    if collapse.continuity_accumulator_hash != expected_accumulator {
        return Err(format!(
            "canonical collapse continuity accumulator mismatch for height {}",
            collapse.height
        ));
    }
    verify_canonical_collapse_recursive_proof_matches_collapse(
        collapse,
        &collapse.continuity_recursive_proof,
        previous,
    )?;
    Ok(())
}

/// Verifies that a block header carries the correct recursive-continuity link.
pub fn verify_block_header_canonical_collapse_link(
    header: &BlockHeader,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    let expected = expected_previous_canonical_collapse_commitment_hash(header.height, previous)?;
    if header.previous_canonical_collapse_commitment_hash != expected {
        return Err(format!(
            "block header canonical collapse continuity commitment hash mismatch for height {}",
            header.height
        ));
    }
    Ok(())
}

/// Verifies the recursive-continuity certificate carried by a block header.
pub fn verify_canonical_collapse_extension_certificate(
    header_height: u64,
    certificate: &CanonicalCollapseExtensionCertificate,
    expected_parent_state_root: [u8; 32],
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    if header_height <= 1 {
        return Err(
            "genesis or height-1 block headers must not carry a canonical collapse extension certificate"
                .into(),
        );
    }

    let predecessor =
        canonical_collapse_extension_predecessor_commitment(header_height, certificate)?;
    if predecessor.resulting_state_root_hash != expected_parent_state_root {
        return Err(format!(
            "canonical collapse extension certificate parent state root mismatch for height {}",
            header_height
        ));
    }
    let previous = previous.ok_or_else(|| {
        format!(
            "missing previous canonical collapse object required to verify extension certificate for height {}",
            header_height
        )
    })?;
    verify_canonical_collapse_recursive_proof(&previous.continuity_recursive_proof)?;
    if canonical_collapse_commitment(previous) != predecessor {
        return Err(format!(
            "canonical collapse extension certificate predecessor commitment does not match locally expected predecessor for height {} (expected {:?}, carried {:?})",
            header_height,
            canonical_collapse_commitment(previous),
            predecessor,
        ));
    }
    let expected_proof_hash =
        canonical_collapse_recursive_proof_hash(&previous.continuity_recursive_proof)?;
    if certificate.predecessor_recursive_proof_hash != expected_proof_hash {
        return Err(format!(
            "canonical collapse extension certificate predecessor proof hash mismatch for height {}",
            header_height
        ));
    }
    Ok(())
}

/// Verifies that a block header carries proof-carrying recursive-continuity evidence.
pub fn verify_block_header_canonical_collapse_evidence(
    header: &BlockHeader,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    if header.height <= 1 {
        verify_block_header_canonical_collapse_link(header, previous)?;
        if header.canonical_collapse_extension_certificate.is_some() {
            return Err(
                "genesis or height-1 block headers must not carry a canonical collapse extension certificate"
                    .into(),
            );
        }
        return Ok(());
    }

    let certificate = header
        .canonical_collapse_extension_certificate
        .as_ref()
        .ok_or_else(|| {
            format!(
                "missing proof-carrying canonical collapse extension certificate for height {}",
                header.height
            )
        })?;
    let expected_parent_state_root =
        to_root_hash(&header.parent_state_root.0).map_err(|e| e.to_string())?;
    verify_canonical_collapse_extension_certificate(
        header.height,
        certificate,
        expected_parent_state_root,
        previous,
    )?;

    let predecessor_commitment_hash =
        canonical_collapse_extension_predecessor_commitment_hash(header.height, certificate)?;
    if predecessor_commitment_hash != header.previous_canonical_collapse_commitment_hash {
        return Err(format!(
            "canonical collapse extension certificate predecessor hash mismatch for height {}",
            header.height
        ));
    }
    if let Some(previous) = previous {
        let expected =
            expected_previous_canonical_collapse_commitment_hash(header.height, Some(previous))?;
        if header.previous_canonical_collapse_commitment_hash != expected {
            return Err(format!(
                "block header canonical collapse continuity commitment hash mismatch for height {}",
                header.height
            ));
        }
    }

    Ok(())
}

fn ensure_sorted_unique_tx_hashes(tx_hashes: &[[u8; 32]]) -> Result<(), String> {
    for window in tx_hashes.windows(2) {
        if window[0] >= window[1] {
            return Err(
                "published bulletin surface must contain strictly increasing unique tx hashes"
                    .into(),
            );
        }
    }
    Ok(())
}

fn build_bulletin_commitment_from_hashes(
    height: u64,
    cutoff_timestamp_ms: u64,
    tx_hashes: &[[u8; 32]],
) -> Result<BulletinCommitment, String> {
    ensure_sorted_unique_tx_hashes(tx_hashes)?;
    let entry_count = u32::try_from(tx_hashes.len())
        .map_err(|_| "too many admitted transactions for bulletin commitment".to_string())?;
    let mut material = Vec::with_capacity(
        b"aft::canonical-order::bulletin::v1".len()
            + std::mem::size_of::<u64>() * 2
            + std::mem::size_of::<u32>()
            + tx_hashes.len() * 32,
    );
    material.extend_from_slice(b"aft::canonical-order::bulletin::v1");
    material.extend_from_slice(&height.to_be_bytes());
    material.extend_from_slice(&cutoff_timestamp_ms.to_be_bytes());
    material.extend_from_slice(&entry_count.to_be_bytes());
    for tx_hash in tx_hashes {
        material.extend_from_slice(tx_hash);
    }
    let bulletin_root = hash_consensus_bytes(&material)?;

    Ok(BulletinCommitment {
        height,
        cutoff_timestamp_ms,
        bulletin_root,
        entry_count,
    })
}

fn canonical_recoverability_root(
    bulletin_commitment: &BulletinCommitment,
    randomness_beacon: &[u8; 32],
    ordered_transactions_root_hash: &[u8; 32],
    resulting_state_root_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    // This root intentionally binds only the committed bulletin / order / post-state
    // surface. Exploratory witness-coded recovery layers must refine it with their
    // own witness and coding inputs rather than treating it as a coded-share root.
    hash_consensus_bytes(&(
        b"aft::canonical-order::recoverability::v1".as_slice(),
        bulletin_commitment,
        randomness_beacon,
        ordered_transactions_root_hash,
        resulting_state_root_hash,
    ))
}

/// Builds the explicit bulletin availability certificate for a canonical order surface.
pub fn build_bulletin_availability_certificate(
    bulletin_commitment: &BulletinCommitment,
    randomness_beacon: &[u8; 32],
    ordered_transactions_root_hash: &[u8; 32],
    resulting_state_root_hash: &[u8; 32],
) -> Result<BulletinAvailabilityCertificate, String> {
    Ok(BulletinAvailabilityCertificate {
        height: bulletin_commitment.height,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(bulletin_commitment)?,
        recoverability_root: canonical_recoverability_root(
            bulletin_commitment,
            randomness_beacon,
            ordered_transactions_root_hash,
            resulting_state_root_hash,
        )?,
    })
}

/// Builds the compact publication availability receipt bound to a canonical order certificate.
pub fn build_publication_availability_receipt(
    certificate: &CanonicalOrderCertificate,
) -> Result<PublicationAvailabilityReceipt, String> {
    Ok(PublicationAvailabilityReceipt {
        height: certificate.height,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(
            &certificate.bulletin_commitment,
        )?,
        ordered_transactions_root_hash: certificate.ordered_transactions_root_hash,
        resulting_state_root_hash: certificate.resulting_state_root_hash,
        receipt_root: certificate
            .bulletin_availability_certificate
            .recoverability_root,
    })
}

/// Verifies a compact publication availability receipt against a canonical order certificate.
pub fn verify_publication_availability_receipt(
    receipt: &PublicationAvailabilityReceipt,
    certificate: &CanonicalOrderCertificate,
) -> Result<(), String> {
    if receipt.height != certificate.height {
        return Err("publication availability receipt height does not match the canonical order certificate".into());
    }
    let expected_commitment_hash =
        canonical_bulletin_commitment_hash(&certificate.bulletin_commitment)?;
    if receipt.bulletin_commitment_hash != expected_commitment_hash {
        return Err(
            "publication availability receipt does not match the bulletin commitment hash".into(),
        );
    }
    if receipt.ordered_transactions_root_hash != certificate.ordered_transactions_root_hash {
        return Err(
            "publication availability receipt does not match the ordered transactions root".into(),
        );
    }
    if receipt.resulting_state_root_hash != certificate.resulting_state_root_hash {
        return Err(
            "publication availability receipt does not match the resulting state root".into(),
        );
    }
    if receipt.receipt_root
        != certificate
            .bulletin_availability_certificate
            .recoverability_root
    {
        return Err(
            "publication availability receipt does not match the recoverability root".into(),
        );
    }
    Ok(())
}

/// Verifies a bulletin availability certificate against its public binding inputs.
pub fn verify_bulletin_availability_binding(
    certificate: &BulletinAvailabilityCertificate,
    bulletin_commitment: &BulletinCommitment,
) -> Result<(), String> {
    if certificate.height != bulletin_commitment.height {
        return Err(
            "bulletin availability certificate height does not match bulletin commitment".into(),
        );
    }
    let expected_commitment_hash = canonical_bulletin_commitment_hash(bulletin_commitment)?;
    if certificate.bulletin_commitment_hash != expected_commitment_hash {
        return Err(
            "bulletin availability certificate does not match the bulletin commitment hash".into(),
        );
    }
    Ok(())
}

/// Verifies a bulletin availability certificate against its public binding inputs.
pub fn verify_bulletin_availability_certificate(
    certificate: &BulletinAvailabilityCertificate,
    bulletin_commitment: &BulletinCommitment,
    randomness_beacon: &[u8; 32],
    ordered_transactions_root_hash: &[u8; 32],
    resulting_state_root_hash: &[u8; 32],
) -> Result<(), String> {
    verify_bulletin_availability_binding(certificate, bulletin_commitment)?;
    let expected_recoverability_root = canonical_recoverability_root(
        bulletin_commitment,
        randomness_beacon,
        ordered_transactions_root_hash,
        resulting_state_root_hash,
    )?;
    if certificate.recoverability_root != expected_recoverability_root {
        return Err(
            "bulletin availability certificate does not match the recoverability root".into(),
        );
    }
    Ok(())
}

fn bulletin_retrievability_geometry(entry_count: u32) -> (u16, u16, u16) {
    if entry_count == 0 {
        (1, 1, 1)
    } else if entry_count <= 8 {
        (3, 2, 2)
    } else {
        (5, 3, 3)
    }
}

fn canonical_bulletin_shard_commitment_root(
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    profile: &BulletinRetrievabilityProfile,
    entries: &[BulletinSurfaceEntry],
) -> Result<[u8; 32], String> {
    let tx_hashes: Vec<[u8; 32]> = entries.iter().map(|entry| entry.tx_hash).collect();
    hash_consensus_bytes(&(
        b"aft::canonical-order::bulletin-shard-manifest::v1".as_slice(),
        bulletin_commitment.height,
        bulletin_commitment.bulletin_root,
        bulletin_availability_certificate.recoverability_root,
        canonical_bulletin_retrievability_profile_hash(profile)?,
        tx_hashes,
    ))
}

fn canonical_bulletin_custody_root(
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(&(
        b"aft::canonical-order::bulletin-custody-receipt::v1".as_slice(),
        canonical_bulletin_retrievability_profile_hash(profile)?,
        canonical_bulletin_shard_manifest_hash(manifest)?,
        manifest.shard_commitment_root,
        profile.custody_threshold,
        profile.shard_count,
    ))
}

fn canonical_bulletin_custody_shard_payload_hash(
    bulletin_commitment: &BulletinCommitment,
    manifest: &BulletinShardManifest,
    assignment_hash: [u8; 32],
    shard_index: u16,
    tx_hashes: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(&(
        b"aft::canonical-order::bulletin-custody-response::v1".as_slice(),
        bulletin_commitment.height,
        bulletin_commitment.bulletin_root,
        canonical_bulletin_shard_manifest_hash(manifest)?,
        assignment_hash,
        shard_index,
        tx_hashes.to_vec(),
    ))
}

fn deterministic_bulletin_shard_sets(
    entries: &[BulletinSurfaceEntry],
    shard_count: u16,
) -> Result<Vec<Vec<[u8; 32]>>, String> {
    if shard_count == 0 {
        return Err("deterministic bulletin shard geometry requires at least one shard".into());
    }
    let mut shards = vec![Vec::new(); usize::from(shard_count)];
    for (index, entry) in entries.iter().enumerate() {
        shards[index % usize::from(shard_count)].push(entry.tx_hash);
    }
    Ok(shards)
}

/// Builds the deterministic bulletin retrievability profile for one slot surface.
pub fn build_bulletin_retrievability_profile(
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
) -> Result<BulletinRetrievabilityProfile, String> {
    verify_bulletin_availability_binding(bulletin_availability_certificate, bulletin_commitment)?;
    let (shard_count, recovery_threshold, custody_threshold) =
        bulletin_retrievability_geometry(bulletin_commitment.entry_count);
    Ok(BulletinRetrievabilityProfile {
        height: bulletin_commitment.height,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(bulletin_commitment)?,
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            bulletin_availability_certificate,
        )?,
        recoverability_root: bulletin_availability_certificate.recoverability_root,
        shard_count,
        recovery_threshold,
        custody_threshold,
    })
}

/// Validates a bulletin retrievability profile against its public slot surface.
pub fn validate_bulletin_retrievability_profile(
    profile: &BulletinRetrievabilityProfile,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
) -> Result<(), String> {
    verify_bulletin_availability_binding(bulletin_availability_certificate, bulletin_commitment)?;
    if profile.height != bulletin_commitment.height {
        return Err(
            "bulletin retrievability profile height does not match the bulletin commitment".into(),
        );
    }
    let expected_commitment_hash = canonical_bulletin_commitment_hash(bulletin_commitment)?;
    if profile.bulletin_commitment_hash != expected_commitment_hash {
        return Err(
            "bulletin retrievability profile does not match the bulletin commitment hash".into(),
        );
    }
    let expected_availability_hash =
        canonical_bulletin_availability_certificate_hash(bulletin_availability_certificate)?;
    if profile.bulletin_availability_certificate_hash != expected_availability_hash {
        return Err(
            "bulletin retrievability profile does not match the bulletin availability certificate hash"
                .into(),
        );
    }
    if profile.recoverability_root != bulletin_availability_certificate.recoverability_root {
        return Err(
            "bulletin retrievability profile does not match the bulletin recoverability root"
                .into(),
        );
    }
    let (expected_shard_count, expected_recovery_threshold, expected_custody_threshold) =
        bulletin_retrievability_geometry(bulletin_commitment.entry_count);
    if profile.shard_count != expected_shard_count
        || profile.recovery_threshold != expected_recovery_threshold
        || profile.custody_threshold != expected_custody_threshold
    {
        return Err(
            "bulletin retrievability profile does not match the deterministic slot geometry"
                .into(),
        );
    }
    Ok(())
}

/// Builds the deterministic bulletin custody assignment for one slot surface from the active
/// validator set.
pub fn build_bulletin_custody_assignment(
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
    validator_set: &ValidatorSetV1,
) -> Result<BulletinCustodyAssignment, String> {
    if manifest.height != profile.height {
        return Err(
            "bulletin custody assignment requires same-height retrievability profile and shard manifest"
                .into(),
        );
    }
    if validator_set.validators.len() < usize::from(profile.shard_count) {
        return Err(
            "bulletin custody assignment requires enough validators to name one deterministic custodian per shard"
                .into(),
        );
    }
    let assignments = validator_set
        .validators
        .iter()
        .take(usize::from(profile.shard_count))
        .enumerate()
        .map(|(index, validator)| BulletinCustodyAssignmentEntry {
            shard_index: index as u16,
            custodian_account_id: validator.account_id,
        })
        .collect::<Vec<_>>();
    Ok(BulletinCustodyAssignment {
        height: profile.height,
        bulletin_commitment_hash: profile.bulletin_commitment_hash,
        bulletin_availability_certificate_hash: profile.bulletin_availability_certificate_hash,
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            profile,
        )?,
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(manifest)?,
        validator_set_commitment_hash: canonical_validator_set_hash(validator_set)?,
        custody_threshold: profile.custody_threshold,
        assignments,
    })
}

/// Validates a bulletin custody assignment against its governing profile, manifest, and effective
/// validator set.
pub fn validate_bulletin_custody_assignment(
    assignment: &BulletinCustodyAssignment,
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
    validator_set: &ValidatorSetV1,
) -> Result<(), String> {
    let expected = build_bulletin_custody_assignment(profile, manifest, validator_set)?;
    if assignment != &expected {
        return Err("bulletin custody assignment does not match the deterministic validator-set assignment".into());
    }
    Ok(())
}

/// Builds the deterministic bulletin shard manifest for one slot surface.
pub fn build_bulletin_shard_manifest(
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    profile: &BulletinRetrievabilityProfile,
    entries: &[BulletinSurfaceEntry],
) -> Result<BulletinShardManifest, String> {
    validate_bulletin_retrievability_profile(
        profile,
        bulletin_commitment,
        bulletin_availability_certificate,
    )?;
    verify_bulletin_surface_entries(bulletin_commitment.height, bulletin_commitment, entries)?;
    Ok(BulletinShardManifest {
        height: bulletin_commitment.height,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(bulletin_commitment)?,
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            bulletin_availability_certificate,
        )?,
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            profile,
        )?,
        recoverability_root: bulletin_availability_certificate.recoverability_root,
        entry_count: bulletin_commitment.entry_count,
        shard_count: profile.shard_count,
        recovery_threshold: profile.recovery_threshold,
        shard_commitment_root: canonical_bulletin_shard_commitment_root(
            bulletin_commitment,
            bulletin_availability_certificate,
            profile,
            entries,
        )?,
    })
}

/// Validates a bulletin shard manifest against its governing slot surface and profile.
pub fn validate_bulletin_shard_manifest(
    manifest: &BulletinShardManifest,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    profile: &BulletinRetrievabilityProfile,
    entries: &[BulletinSurfaceEntry],
) -> Result<(), String> {
    validate_bulletin_retrievability_profile(
        profile,
        bulletin_commitment,
        bulletin_availability_certificate,
    )?;
    verify_bulletin_surface_entries(bulletin_commitment.height, bulletin_commitment, entries)?;
    if manifest.height != bulletin_commitment.height {
        return Err("bulletin shard manifest height does not match the bulletin commitment".into());
    }
    let expected_commitment_hash = canonical_bulletin_commitment_hash(bulletin_commitment)?;
    if manifest.bulletin_commitment_hash != expected_commitment_hash {
        return Err("bulletin shard manifest does not match the bulletin commitment hash".into());
    }
    let expected_availability_hash =
        canonical_bulletin_availability_certificate_hash(bulletin_availability_certificate)?;
    if manifest.bulletin_availability_certificate_hash != expected_availability_hash {
        return Err(
            "bulletin shard manifest does not match the bulletin availability certificate hash"
                .into(),
        );
    }
    let expected_profile_hash = canonical_bulletin_retrievability_profile_hash(profile)?;
    if manifest.bulletin_retrievability_profile_hash != expected_profile_hash {
        return Err("bulletin shard manifest does not match the retrievability profile hash".into());
    }
    if manifest.recoverability_root != bulletin_availability_certificate.recoverability_root {
        return Err("bulletin shard manifest does not match the recoverability root".into());
    }
    if manifest.entry_count != bulletin_commitment.entry_count
        || manifest.shard_count != profile.shard_count
        || manifest.recovery_threshold != profile.recovery_threshold
    {
        return Err("bulletin shard manifest does not match the deterministic shard geometry".into());
    }
    let expected_shard_root = canonical_bulletin_shard_commitment_root(
        bulletin_commitment,
        bulletin_availability_certificate,
        profile,
        entries,
    )?;
    if manifest.shard_commitment_root != expected_shard_root {
        return Err("bulletin shard manifest does not match the deterministic shard commitment root".into());
    }
    Ok(())
}

/// Builds the deterministic bulletin custody receipt for one slot surface.
pub fn build_bulletin_custody_receipt(
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
) -> Result<BulletinCustodyReceipt, String> {
    if manifest.height != profile.height {
        return Err(
            "bulletin custody receipt requires same-height retrievability profile and shard manifest"
                .into(),
        );
    }
    Ok(BulletinCustodyReceipt {
        height: profile.height,
        bulletin_commitment_hash: profile.bulletin_commitment_hash,
        bulletin_availability_certificate_hash: profile.bulletin_availability_certificate_hash,
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            profile,
        )?,
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(manifest)?,
        custodian_count: profile.shard_count,
        custody_threshold: profile.custody_threshold,
        custody_root: canonical_bulletin_custody_root(profile, manifest)?,
    })
}

/// Validates a bulletin custody receipt against its governing profile and manifest.
pub fn validate_bulletin_custody_receipt(
    receipt: &BulletinCustodyReceipt,
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
) -> Result<(), String> {
    if receipt.height != profile.height || receipt.height != manifest.height {
        return Err(
            "bulletin custody receipt height does not match the retrievability profile and shard manifest"
                .into(),
        );
    }
    if receipt.bulletin_commitment_hash != profile.bulletin_commitment_hash
        || receipt.bulletin_commitment_hash != manifest.bulletin_commitment_hash
    {
        return Err("bulletin custody receipt does not match the bulletin commitment hash".into());
    }
    if receipt.bulletin_availability_certificate_hash
        != profile.bulletin_availability_certificate_hash
        || receipt.bulletin_availability_certificate_hash
            != manifest.bulletin_availability_certificate_hash
    {
        return Err(
            "bulletin custody receipt does not match the bulletin availability certificate hash"
                .into(),
        );
    }
    let expected_profile_hash = canonical_bulletin_retrievability_profile_hash(profile)?;
    if receipt.bulletin_retrievability_profile_hash != expected_profile_hash {
        return Err("bulletin custody receipt does not match the retrievability profile hash".into());
    }
    let expected_manifest_hash = canonical_bulletin_shard_manifest_hash(manifest)?;
    if receipt.bulletin_shard_manifest_hash != expected_manifest_hash {
        return Err("bulletin custody receipt does not match the shard manifest hash".into());
    }
    if receipt.custodian_count != profile.shard_count
        || receipt.custody_threshold != profile.custody_threshold
    {
        return Err("bulletin custody receipt does not match the deterministic custody geometry".into());
    }
    let expected_custody_root = canonical_bulletin_custody_root(profile, manifest)?;
    if receipt.custody_root != expected_custody_root {
        return Err("bulletin custody receipt does not match the deterministic custody root".into());
    }
    Ok(())
}

/// Builds the deterministic bulletin custody response for one slot surface from the governing
/// assignment and the published bulletin entries.
pub fn build_bulletin_custody_response(
    bulletin_commitment: &BulletinCommitment,
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
    assignment: &BulletinCustodyAssignment,
    receipt: &BulletinCustodyReceipt,
    entries: &[BulletinSurfaceEntry],
) -> Result<BulletinCustodyResponse, String> {
    validate_bulletin_custody_receipt(receipt, profile, manifest)?;
    if assignment.height != bulletin_commitment.height {
        return Err(
            "bulletin custody response requires same-height bulletin commitment and custody assignment"
                .into(),
        );
    }
    let assignment_hash = canonical_bulletin_custody_assignment_hash(assignment)?;
    let shard_sets = deterministic_bulletin_shard_sets(entries, profile.shard_count)?;
    let mut served_shards = Vec::with_capacity(assignment.assignments.len());
    for assignment_entry in &assignment.assignments {
        let shard_entries = shard_sets
            .get(usize::from(assignment_entry.shard_index))
            .ok_or_else(|| "bulletin custody response assignment references a shard beyond the deterministic shard set".to_string())?;
        served_shards.push(BulletinCustodyServedShard {
            shard_index: assignment_entry.shard_index,
            custodian_account_id: assignment_entry.custodian_account_id,
            served_entry_count: shard_entries.len() as u32,
            served_shard_hash: canonical_bulletin_custody_shard_payload_hash(
                bulletin_commitment,
                manifest,
                assignment_hash,
                assignment_entry.shard_index,
                shard_entries,
            )?,
        });
    }
    Ok(BulletinCustodyResponse {
        height: bulletin_commitment.height,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(bulletin_commitment)?,
        bulletin_availability_certificate_hash: profile.bulletin_availability_certificate_hash,
        bulletin_retrievability_profile_hash: canonical_bulletin_retrievability_profile_hash(
            profile,
        )?,
        bulletin_shard_manifest_hash: canonical_bulletin_shard_manifest_hash(manifest)?,
        bulletin_custody_assignment_hash: assignment_hash,
        bulletin_custody_receipt_hash: canonical_bulletin_custody_receipt_hash(receipt)?,
        served_shards,
    })
}

/// Validates a bulletin custody response against its deterministic shard assignments and bulletin
/// entry surface.
pub fn validate_bulletin_custody_response(
    response: &BulletinCustodyResponse,
    bulletin_commitment: &BulletinCommitment,
    profile: &BulletinRetrievabilityProfile,
    manifest: &BulletinShardManifest,
    assignment: &BulletinCustodyAssignment,
    receipt: &BulletinCustodyReceipt,
    entries: &[BulletinSurfaceEntry],
) -> Result<(), String> {
    let expected = build_bulletin_custody_response(
        bulletin_commitment,
        profile,
        manifest,
        assignment,
        receipt,
        entries,
    )?;
    if response != &expected {
        return Err(
            "bulletin custody response does not match the deterministic shard-service surface"
                .into(),
        );
    }
    Ok(())
}

/// Validates objective fail-closed evidence over the endogenous bulletin retrievability surface.
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
            if !entries.is_empty() {
                return Err(
                    "missing surface entries challenge requires the bulletin entry surface to be absent"
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
