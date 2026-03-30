/// Returns the canonical hash of an assigned recovery-share delivery envelope.
pub fn canonical_assigned_recovery_share_envelope_hash(
    envelope: &AssignedRecoveryShareEnvelopeV1,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(envelope)
}

/// Returns the canonical hash of the compact recovery slot payload.
pub fn canonical_recoverable_slot_payload_hash(
    payload: &RecoverableSlotPayloadV1,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of the widened recovery slot payload.
pub fn canonical_recoverable_slot_payload_v2_hash(
    payload: &RecoverableSlotPayloadV2,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of the publication-oriented recovery slot payload.
pub fn canonical_recoverable_slot_payload_v3_hash(
    payload: &RecoverableSlotPayloadV3,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of the close-extraction recovery slot payload.
pub fn canonical_recoverable_slot_payload_v4_hash(
    payload: &RecoverableSlotPayloadV4,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of the explicit bulletin-surface recovery slot payload.
pub fn canonical_recoverable_slot_payload_v5_hash(
    payload: &RecoverableSlotPayloadV5,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of an atomic canonical-order publication bundle.
pub fn canonical_order_publication_bundle_hash(
    bundle: &CanonicalOrderPublicationBundle,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(bundle)
}

/// Returns the canonical hash of an exploratory missing-recovery-share claim.
pub fn canonical_missing_recovery_share_hash(
    missing_share: &MissingRecoveryShare,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(missing_share)
}

/// Returns the canonical hash of a bulletin-close object.
pub fn canonical_bulletin_close_hash(close: &CanonicalBulletinClose) -> Result<[u8; 32], String> {
    hash_consensus_bytes(close)
}

/// Returns the canonical hash of a canonical-order certificate.
pub fn canonical_order_certificate_hash(
    certificate: &CanonicalOrderCertificate,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(certificate)
}

/// Returns the canonical hash of a canonical-order abort object.
pub fn canonical_order_abort_hash(abort: &CanonicalOrderAbort) -> Result<[u8; 32], String> {
    hash_consensus_bytes(abort)
}

/// Returns the canonical hash of a publication availability receipt.
pub fn canonical_publication_availability_receipt_hash(
    receipt: &PublicationAvailabilityReceipt,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(receipt)
}

/// Returns the canonical hash of a compact publication frontier.
pub fn canonical_publication_frontier_hash(
    frontier: &PublicationFrontier,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(frontier)
}

/// Returns the canonical hash of a publication-frontier contradiction witness.
pub fn canonical_publication_frontier_contradiction_hash(
    contradiction: &PublicationFrontierContradiction,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(contradiction)
}

/// Canonicalizes the witness support set carried by a recovered-publication bundle.
pub fn normalize_recovered_publication_bundle_supporting_witnesses(
    supporting_witness_manifest_hashes: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, String> {
    if supporting_witness_manifest_hashes.is_empty() {
        return Err(
            "recovered publication bundle requires at least one supporting witness manifest".into(),
        );
    }
    if supporting_witness_manifest_hashes
        .iter()
        .any(|manifest_hash| *manifest_hash == [0u8; 32])
    {
        return Err(
            "recovered publication bundle supporting witness manifests must be non-zero".into(),
        );
    }
    let mut normalized = supporting_witness_manifest_hashes.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    if normalized.len() != supporting_witness_manifest_hashes.len() {
        return Err(
            "recovered publication bundle supporting witness manifests must be distinct".into(),
        );
    }
    Ok(normalized)
}

/// Returns the canonical support-set hash for a recovered-publication bundle.
pub fn canonical_recovered_publication_bundle_support_hash(
    supporting_witness_manifest_hashes: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    let normalized = normalize_recovered_publication_bundle_supporting_witnesses(
        supporting_witness_manifest_hashes,
    )?;
    hash_consensus_bytes(&(
        b"aft::recovery::recovered_publication_bundle::support::v1",
        normalized,
    ))
}

fn xor_recovery_share_material_bytes(left: &[u8], right: &[u8]) -> Result<Vec<u8>, String> {
    if left.len() != right.len() {
        return Err("systematic xor shard operands must have identical lengths".into());
    }
    Ok(left.iter().zip(right.iter()).map(|(a, b)| a ^ b).collect())
}

const GF256_REDUCTION_POLYNOMIAL: u8 = 0x1D;

fn gf256_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0u8;
    while right != 0 {
        if right & 1 != 0 {
            product ^= left;
        }
        let carry = left & 0x80 != 0;
        left <<= 1;
        if carry {
            left ^= GF256_REDUCTION_POLYNOMIAL;
        }
        right >>= 1;
    }
    product
}

fn gf256_inv(value: u8) -> Result<u8, String> {
    if value == 0 {
        return Err("gf256 inverse is undefined for zero".into());
    }
    for candidate in 1..=u8::MAX {
        if gf256_mul(value, candidate) == 1 {
            return Ok(candidate);
        }
    }
    Err("gf256 inverse does not exist for the provided coefficient".into())
}

fn gf256_scale_bytes(coeff: u8, shard: &[u8]) -> Vec<u8> {
    shard.iter().map(|byte| gf256_mul(coeff, *byte)).collect()
}

fn systematic_gf256_geometry(coding: RecoveryCodingDescriptor) -> Option<(usize, usize)> {
    (coding.is_systematic_gf256_k_of_n_family() && coding.validate().is_ok()).then_some((
        usize::from(coding.recovery_threshold),
        usize::from(coding.share_count),
    ))
}

fn decode_recovery_payload_frame(framed: &[u8], scheme: &str) -> Result<Vec<u8>, String> {
    if framed.len() < 4 {
        return Err(format!(
            "{scheme} reconstruction produced an undersized payload frame"
        ));
    }
    let payload_len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
    let frame_len = 4usize
        .checked_add(payload_len)
        .ok_or_else(|| format!("{scheme} reconstruction payload length overflow"))?;
    if frame_len > framed.len() {
        return Err(format!(
            "{scheme} reconstruction produced an invalid payload length"
        ));
    }
    Ok(framed[4..frame_len].to_vec())
}

fn encode_recovery_payload_frame(
    payload_bytes: &[u8],
    data_shard_count: usize,
    scheme: &str,
) -> Result<(Vec<Vec<u8>>, usize), String> {
    if data_shard_count < 2 {
        return Err(format!("{scheme} shards require threshold at least two"));
    }
    let payload_len = u32::try_from(payload_bytes.len())
        .map_err(|_| format!("{scheme} payload exceeds 4 GiB bound"))?;
    let mut framed = Vec::with_capacity(4 + payload_bytes.len());
    framed.extend_from_slice(&payload_len.to_be_bytes());
    framed.extend_from_slice(payload_bytes);
    let shard_len = framed.len().div_ceil(data_shard_count);
    framed.resize(shard_len * data_shard_count, 0);
    Ok((
        framed
            .chunks(shard_len)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>(),
        shard_len,
    ))
}

pub(super) fn encode_systematic_xor_k_of_k_plus_1_shards(
    payload_bytes: &[u8],
    recovery_threshold: u16,
) -> Result<Vec<Vec<u8>>, String> {
    let scheme = "systematic xor parity";
    let (mut shards, shard_len) =
        encode_recovery_payload_frame(payload_bytes, usize::from(recovery_threshold), scheme)?;
    let mut parity = vec![0u8; shard_len];
    for shard in &shards {
        for (slot, value) in parity.iter_mut().zip(shard.iter()) {
            *slot ^= *value;
        }
    }
    shards.push(parity);
    Ok(shards)
}

pub(super) fn encode_systematic_gf256_k_of_n_shards(
    payload_bytes: &[u8],
    share_count: u16,
    recovery_threshold: u16,
) -> Result<Vec<Vec<u8>>, String> {
    let scheme = "systematic gf256";
    if recovery_threshold < 2 {
        return Err(format!("{scheme} shards require threshold at least two"));
    }
    if share_count < recovery_threshold.saturating_add(2) {
        return Err(format!(
            "{scheme} shards require at least two parity shares"
        ));
    }
    let parity_shard_count = share_count.saturating_sub(recovery_threshold);
    if parity_shard_count > u16::from(u8::MAX) {
        return Err(format!("{scheme} shards support at most 255 parity shares"));
    }
    if share_count > u16::from(u8::MAX) + 1 {
        return Err(format!("{scheme} shards support at most 256 total shares"));
    }

    let (data_shards, shard_len) =
        encode_recovery_payload_frame(payload_bytes, usize::from(recovery_threshold), scheme)?;
    let mut shards = data_shards.clone();
    for parity_share_index in usize::from(recovery_threshold)..usize::from(share_count) {
        let mut parity = vec![0u8; shard_len];
        for (data_index, shard) in data_shards.iter().enumerate() {
            let coeff = systematic_gf256_parity_coefficient(
                data_index,
                parity_share_index,
                usize::from(recovery_threshold),
                usize::from(share_count),
                scheme,
            )?;
            let scaled = gf256_scale_bytes(coeff, shard);
            for (slot, value) in parity.iter_mut().zip(scaled.iter()) {
                *slot ^= *value;
            }
        }
        shards.push(parity);
    }
    Ok(shards)
}

/// Encodes a recoverable slot payload into deterministic share bytes for the
/// provided recovery coding descriptor.
pub fn encode_coded_recovery_shards(
    coding: RecoveryCodingDescriptor,
    payload_bytes: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    coding
        .family_contract()?
        .encode_payload_shards(payload_bytes)
}

pub(super) fn is_systematic_xor_parity_coding(coding: RecoveryCodingDescriptor) -> bool {
    coding.is_systematic_xor_parity_family() && coding.validate().is_ok()
}

pub(super) fn is_systematic_gf256_coding(coding: RecoveryCodingDescriptor) -> bool {
    systematic_gf256_geometry(coding).is_some()
}

pub(super) fn recover_systematic_xor_k_of_k_plus_1_slot_payload_bytes(
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<u8>, String> {
    let mut unique = materials
        .iter()
        .filter(|material| is_systematic_xor_parity_coding(material.coding))
        .collect::<Vec<_>>();
    unique.sort_by_key(|material| material.share_index);

    let mut deduplicated: Vec<&RecoveryShareMaterial> = Vec::new();
    for material in unique {
        if let Some(previous) = deduplicated.last() {
            if previous.share_index == material.share_index {
                if *previous != material {
                    return Err(
                        "systematic xor reconstruction encountered conflicting reveals for one share index"
                            .into(),
                    );
                }
                continue;
            }
        }
        deduplicated.push(material);
    }

    let Some(first) = deduplicated.first().copied() else {
        return Err(
            "systematic xor parity reconstruction requires at least one share reveal".into(),
        );
    };
    let share_count = usize::from(first.coding.share_count);
    let recovery_threshold = usize::from(first.coding.recovery_threshold);
    if recovery_threshold < 2 {
        return Err("systematic xor parity reconstruction requires threshold at least two".into());
    }
    if share_count != recovery_threshold + 1 {
        return Err(
            "systematic xor parity reconstruction requires share_count = recovery_threshold + 1"
                .into(),
        );
    }
    if deduplicated.len() < recovery_threshold {
        return Err(format!(
            "systematic xor parity reconstruction requires at least {recovery_threshold} distinct share reveals"
        ));
    }
    let shard_len = first.material_bytes.len();
    let parity_index = recovery_threshold;
    let mut shard_by_index = vec![None; share_count];
    for material in &deduplicated {
        if usize::from(material.coding.share_count) != share_count
            || usize::from(material.coding.recovery_threshold) != recovery_threshold
        {
            return Err(
                "systematic xor parity reconstruction requires consistent share geometry".into(),
            );
        }
        if material.height != first.height
            || material.block_commitment_hash != first.block_commitment_hash
        {
            return Err(
                "systematic xor parity reconstruction requires shares from the same slot commitment"
                    .into(),
            );
        }
        if !is_systematic_xor_parity_coding(material.coding) {
            return Err(
                "systematic xor parity reconstruction encountered a non-parity share kind".into(),
            );
        }
        if material.material_bytes.len() != shard_len {
            return Err(
                "systematic xor parity reconstruction requires equal-length shard materials".into(),
            );
        }
        let share_index = usize::from(material.share_index);
        if share_index >= share_count {
            return Err(
                "systematic xor parity reconstruction encountered an out-of-range share index"
                    .into(),
            );
        }
        shard_by_index[share_index] = Some(material.material_bytes.clone());
    }

    let mut data_shards = vec![Vec::new(); recovery_threshold];
    let missing_indices = shard_by_index
        .iter()
        .enumerate()
        .filter_map(|(index, shard)| shard.is_none().then_some(index))
        .collect::<Vec<_>>();
    if missing_indices.len() > 1 {
        return Err(
            "systematic xor parity reconstruction cannot recover more than one missing shard"
                .into(),
        );
    }
    if missing_indices.is_empty() || missing_indices[0] == parity_index {
        for (index, shard) in shard_by_index.iter().take(recovery_threshold).enumerate() {
            data_shards[index] = shard
                .clone()
                .ok_or_else(|| {
                    "systematic xor parity reconstruction requires all data shards when parity is missing"
                        .to_string()
                })?;
        }
    } else {
        let missing_data_index = missing_indices[0];
        let parity = shard_by_index[parity_index].as_ref().ok_or_else(|| {
            "systematic xor parity reconstruction requires the parity shard when one data shard is missing"
                .to_string()
        })?;
        let mut reconstructed = parity.clone();
        for (index, shard) in shard_by_index.iter().take(recovery_threshold).enumerate() {
            if index == missing_data_index {
                continue;
            }
            let shard = shard.as_ref().ok_or_else(|| {
                "systematic xor parity reconstruction requires all other data shards".to_string()
            })?;
            reconstructed = xor_recovery_share_material_bytes(&reconstructed, shard)?;
            data_shards[index] = shard.clone();
        }
        data_shards[missing_data_index] = reconstructed;
    }

    let mut framed = Vec::with_capacity(recovery_threshold * shard_len);
    for shard in data_shards {
        framed.extend_from_slice(&shard);
    }
    decode_recovery_payload_frame(&framed, "systematic xor parity")
}

fn systematic_gf256_parity_coefficient(
    data_index: usize,
    parity_share_index: usize,
    recovery_threshold: usize,
    share_count: usize,
    scheme: &str,
) -> Result<u8, String> {
    if data_index >= recovery_threshold {
        return Err(format!(
            "{scheme} reconstruction encountered an out-of-range data shard index"
        ));
    }
    if parity_share_index < recovery_threshold || parity_share_index >= share_count {
        return Err(format!(
            "{scheme} reconstruction encountered an out-of-range parity share index"
        ));
    }

    let data_point = u8::try_from(data_index)
        .map_err(|_| format!("{scheme} reconstruction data point exceeds u8"))?;
    let parity_point = u8::try_from(parity_share_index)
        .map_err(|_| format!("{scheme} reconstruction parity point exceeds u8"))?;
    let denominator = data_point ^ parity_point;
    if denominator == 0 {
        return Err(format!(
            "{scheme} reconstruction parity coefficient denominator vanished"
        ));
    }
    gf256_inv(denominator)
}

fn systematic_gf256_row(
    share_index: usize,
    recovery_threshold: usize,
    share_count: usize,
    scheme: &str,
) -> Result<Vec<u8>, String> {
    if share_count <= recovery_threshold {
        return Err(format!(
            "{scheme} reconstruction requires at least one parity share"
        ));
    }
    if share_index >= share_count {
        return Err(format!(
            "{scheme} reconstruction encountered an out-of-range share index"
        ));
    }
    if share_index < recovery_threshold {
        let mut row = vec![0u8; recovery_threshold];
        row[share_index] = 1;
        return Ok(row);
    }

    (0..recovery_threshold)
        .map(|data_index| {
            systematic_gf256_parity_coefficient(
                data_index,
                share_index,
                recovery_threshold,
                share_count,
                scheme,
            )
        })
        .collect()
}

fn invert_gf256_matrix(matrix: &[Vec<u8>], scheme: &str) -> Result<Vec<Vec<u8>>, String> {
    let dimension = matrix.len();
    if dimension == 0 {
        return Err(format!(
            "{scheme} reconstruction requires a non-empty matrix"
        ));
    }
    if matrix.iter().any(|row| row.len() != dimension) {
        return Err(format!(
            "{scheme} reconstruction requires a square coefficient matrix"
        ));
    }

    let mut left = matrix.to_vec();
    let mut right = vec![vec![0u8; dimension]; dimension];
    for (index, row) in right.iter_mut().enumerate() {
        row[index] = 1;
    }

    for pivot_index in 0..dimension {
        let pivot_row = (pivot_index..dimension)
            .find(|row_index| left[*row_index][pivot_index] != 0)
            .ok_or_else(|| {
                format!("{scheme} reconstruction requires linearly independent share rows")
            })?;
        if pivot_row != pivot_index {
            left.swap(pivot_index, pivot_row);
            right.swap(pivot_index, pivot_row);
        }

        let inverse_pivot = gf256_inv(left[pivot_index][pivot_index])?;
        for column in 0..dimension {
            left[pivot_index][column] = gf256_mul(left[pivot_index][column], inverse_pivot);
            right[pivot_index][column] = gf256_mul(right[pivot_index][column], inverse_pivot);
        }

        for row_index in 0..dimension {
            if row_index == pivot_index {
                continue;
            }
            let factor = left[row_index][pivot_index];
            if factor == 0 {
                continue;
            }
            for column in 0..dimension {
                left[row_index][column] ^= gf256_mul(factor, left[pivot_index][column]);
                right[row_index][column] ^= gf256_mul(factor, right[pivot_index][column]);
            }
        }
    }

    Ok(right)
}

pub(super) fn recover_systematic_gf256_k_of_n_slot_payload_bytes(
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<u8>, String> {
    let mut unique = materials
        .iter()
        .filter(|material| is_systematic_gf256_coding(material.coding))
        .collect::<Vec<_>>();
    unique.sort_by_key(|material| material.share_index);

    let mut deduplicated: Vec<&RecoveryShareMaterial> = Vec::new();
    for material in unique {
        if let Some(previous) = deduplicated.last() {
            if previous.share_index == material.share_index {
                if *previous != material {
                    return Err(
                        "systematic gf256 reconstruction encountered conflicting reveals for one share index"
                            .into(),
                    );
                }
                continue;
            }
        }
        deduplicated.push(material);
    }

    let Some(first) = deduplicated.first().copied() else {
        return Err("systematic gf256 reconstruction requires at least one share reveal".into());
    };
    let (recovery_threshold, share_count) =
        systematic_gf256_geometry(first.coding).ok_or_else(|| {
            "systematic gf256 reconstruction requires a supported gf256 materialization kind"
                .to_string()
        })?;
    let scheme = first.coding.label();
    if usize::from(first.coding.share_count) != share_count {
        return Err(format!(
            "{scheme} reconstruction requires share_count = {share_count}"
        ));
    }
    if usize::from(first.coding.recovery_threshold) != recovery_threshold {
        return Err(format!(
            "{scheme} reconstruction requires recovery_threshold = {recovery_threshold}"
        ));
    }
    if deduplicated.len() < recovery_threshold {
        return Err(format!(
            "{scheme} reconstruction requires at least {recovery_threshold} distinct share reveals"
        ));
    }

    let shard_len = first.material_bytes.len();
    for material in &deduplicated {
        if material.coding.share_count != first.coding.share_count
            || material.coding.recovery_threshold != first.coding.recovery_threshold
        {
            return Err(format!(
                "{scheme} reconstruction requires consistent share geometry"
            ));
        }
        if material.height != first.height
            || material.block_commitment_hash != first.block_commitment_hash
        {
            return Err(format!(
                "{scheme} reconstruction requires shares from the same slot commitment"
            ));
        }
        if material.coding != first.coding {
            return Err(format!(
                "{scheme} reconstruction requires a uniform gf256 materialization kind"
            ));
        }
        if material.material_bytes.len() != shard_len {
            return Err(format!(
                "{scheme} reconstruction requires equal-length shard materials"
            ));
        }
        if usize::from(material.share_index) >= share_count {
            return Err(format!(
                "{scheme} reconstruction encountered an out-of-range share index"
            ));
        }
    }

    let selected = deduplicated
        .iter()
        .take(recovery_threshold)
        .copied()
        .collect::<Vec<_>>();
    let coefficient_rows = selected
        .iter()
        .map(|material| {
            systematic_gf256_row(
                usize::from(material.share_index),
                recovery_threshold,
                share_count,
                &scheme,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inverse = invert_gf256_matrix(&coefficient_rows, &scheme)?;
    let selected_shards = selected
        .iter()
        .map(|material| material.material_bytes.as_slice())
        .collect::<Vec<_>>();

    let mut data_shards = Vec::with_capacity(recovery_threshold);
    for row in &inverse {
        let mut shard = vec![0u8; shard_len];
        for (coeff, selected_shard) in row.iter().zip(selected_shards.iter()) {
            if *coeff == 0 {
                continue;
            }
            let scaled = gf256_scale_bytes(*coeff, selected_shard);
            for (byte, scaled_byte) in shard.iter_mut().zip(scaled.iter()) {
                *byte ^= *scaled_byte;
            }
        }
        data_shards.push(shard);
    }

    let mut framed = Vec::with_capacity(recovery_threshold * shard_len);
    for shard in data_shards {
        framed.extend_from_slice(&shard);
    }
    decode_recovery_payload_frame(&framed, &scheme)
}

/// Reconstructs a `RecoverableSlotPayloadV3` from public share reveals.
pub fn recover_recoverable_slot_payload_v3_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<RecoverableSlotPayloadV3, String> {
    let Some(first) = materials.first() else {
        return Err(
            "recoverable slot payload reconstruction requires at least one share reveal".into(),
        );
    };
    let payload_bytes = first
        .coding
        .family_contract()?
        .recover_payload_bytes_from_materials(materials)?;
    codec::from_bytes_canonical(&payload_bytes).map_err(|error| error.to_string())
}

/// Reconstructs and verifies a canonical-order publication bundle from public share reveals.
pub fn recover_canonical_order_publication_bundle_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<(RecoverableSlotPayloadV3, CanonicalOrderPublicationBundle), String> {
    let payload = recover_recoverable_slot_payload_v3_from_share_materials(materials)?;
    let bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&payload.canonical_order_publication_bundle_bytes)
            .map_err(|error| error.to_string())?;
    verify_canonical_order_publication_bundle(&bundle)?;
    Ok((payload, bundle))
}

/// Lifts a recovered `RecoverableSlotPayloadV3` into the explicit positive
/// close-extraction `RecoverableSlotPayloadV4` surface.
pub fn lift_recoverable_slot_payload_v3_to_v4(
    payload: &RecoverableSlotPayloadV3,
) -> Result<
    (
        RecoverableSlotPayloadV4,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
    ),
    String,
> {
    let bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&payload.canonical_order_publication_bundle_bytes)
            .map_err(|error| error.to_string())?;
    let bulletin_close = verify_canonical_order_publication_bundle(&bundle)?;
    let payload_v4 = RecoverableSlotPayloadV4 {
        height: payload.height,
        view: payload.view,
        producer_account_id: payload.producer_account_id,
        block_commitment_hash: payload.block_commitment_hash,
        parent_block_hash: payload.parent_block_hash,
        canonical_order_certificate: payload.canonical_order_certificate.clone(),
        ordered_transaction_bytes: payload.ordered_transaction_bytes.clone(),
        canonical_order_publication_bundle_bytes: payload
            .canonical_order_publication_bundle_bytes
            .clone(),
        canonical_bulletin_close_bytes: codec::to_bytes_canonical(&bulletin_close)
            .map_err(|error| error.to_string())?,
    };
    Ok((payload_v4, bundle, bulletin_close))
}

/// Lifts a recovered `RecoverableSlotPayloadV4` into the explicit extractable
/// bulletin-surface `RecoverableSlotPayloadV5`.
pub fn lift_recoverable_slot_payload_v4_to_v5(
    payload: &RecoverableSlotPayloadV4,
) -> Result<
    (
        RecoverableSlotPayloadV5,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
        Vec<BulletinSurfaceEntry>,
    ),
    String,
> {
    let bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&payload.canonical_order_publication_bundle_bytes)
            .map_err(|error| error.to_string())?;
    let bundle_close = verify_canonical_order_publication_bundle(&bundle)?;
    let bulletin_close: CanonicalBulletinClose =
        codec::from_bytes_canonical(&payload.canonical_bulletin_close_bytes)
            .map_err(|error| error.to_string())?;
    if bulletin_close != bundle_close {
        return Err(
            "recoverable slot payload v5 requires bulletin-close bytes that match the recovered publication bundle"
                .into(),
        );
    }
    let bulletin_surface_entries = extract_canonical_bulletin_surface(
        &bulletin_close,
        &bundle.bulletin_commitment,
        &bundle.bulletin_availability_certificate,
        &bundle.bulletin_entries,
    )?;
    let payload_v5 = RecoverableSlotPayloadV5 {
        height: payload.height,
        view: payload.view,
        producer_account_id: payload.producer_account_id.clone(),
        block_commitment_hash: payload.block_commitment_hash,
        parent_block_hash: payload.parent_block_hash,
        canonical_order_certificate: payload.canonical_order_certificate.clone(),
        ordered_transaction_bytes: payload.ordered_transaction_bytes.clone(),
        canonical_order_publication_bundle_bytes: payload
            .canonical_order_publication_bundle_bytes
            .clone(),
        canonical_bulletin_close_bytes: payload.canonical_bulletin_close_bytes.clone(),
        canonical_bulletin_availability_certificate_bytes: codec::to_bytes_canonical(
            &bundle.bulletin_availability_certificate,
        )
        .map_err(|error| error.to_string())?,
        bulletin_surface_entries: bulletin_surface_entries.clone(),
    };
    Ok((payload_v5, bundle, bulletin_close, bulletin_surface_entries))
}

/// Reconstructs the explicit positive canonical-order close surface from
/// public share reveals.
pub fn recover_canonical_order_artifact_surface_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<
    (
        RecoverableSlotPayloadV4,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
    ),
    String,
> {
    let (payload_v3, _) =
        recover_canonical_order_publication_bundle_from_share_materials(materials)?;
    lift_recoverable_slot_payload_v3_to_v4(&payload_v3)
}

/// Reconstructs the full extractable canonical-order bulletin surface from
/// public share reveals.
pub fn recover_full_canonical_order_surface_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<
    (
        RecoverableSlotPayloadV5,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
        Vec<BulletinSurfaceEntry>,
    ),
    String,
> {
    let (payload_v4, _, _) =
        recover_canonical_order_artifact_surface_from_share_materials(materials)?;
    lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
}

