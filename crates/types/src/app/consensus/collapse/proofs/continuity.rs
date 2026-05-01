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
    } else if let Some(previous) = previous {
        canonical_collapse_recursive_proof_hash(previous)?
    } else {
        [0u8; 32]
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
    } else if proof.previous_canonical_collapse_commitment_hash == [0u8; 32] {
        if proof.previous_recursive_proof_hash != [0u8; 32] {
            return Err(format!(
                "canonical collapse proof at height {} carries a bootstrap predecessor commitment but a non-zero predecessor proof hash",
                proof.commitment.height
            ));
        }
    } else if proof.previous_recursive_proof_hash == [0u8; 32] {
        return Err(format!(
            "canonical collapse proof at height {} must carry a non-zero predecessor proof hash",
            proof.commitment.height
        ));
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
    let Some(previous) = previous else {
        if proof.previous_canonical_collapse_commitment_hash == [0u8; 32]
            && proof.previous_recursive_proof_hash == [0u8; 32]
        {
            return Ok(());
        }
        return Err(format!(
            "canonical collapse proof at height {} requires an anchored predecessor collapse object",
            collapse.height
        ));
    };
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
    if height <= 1 || previous.is_none() {
        return Ok([0u8; 32]);
    }

    let previous = previous.expect("checked above");
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
    if height <= 1 || previous.is_none() {
        return Ok([0u8; 32]);
    }

    let previous = previous.expect("checked above");
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
