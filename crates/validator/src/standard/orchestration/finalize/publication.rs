use super::*;

pub(super) struct CanonicalObserverPublicationArtifacts {
    transcripts: Vec<AsymptoteObserverTranscript>,
    challenges: Vec<AsymptoteObserverChallenge>,
    transcript_commitment: AsymptoteObserverTranscriptCommitment,
    challenge_commitment: AsymptoteObserverChallengeCommitment,
    canonical_close: Option<AsymptoteObserverCanonicalClose>,
    canonical_abort: Option<AsymptoteObserverCanonicalAbort>,
}

#[derive(Debug, Clone)]
pub(super) struct CanonicalOrderPublicationArtifacts {
    bundle: Option<CanonicalOrderPublicationBundle>,
    publication_frontier: Option<PublicationFrontier>,
    canonical_abort: Option<CanonicalOrderAbort>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExperimentalRecoveryScaffoldArtifacts {
    capsule: RecoveryCapsule,
    share_commitment_hash: [u8; 32],
}

impl ExperimentalRecoveryScaffoldArtifacts {
    pub(super) fn recovery_binding(&self) -> Result<GuardianWitnessRecoveryBinding> {
        Ok(GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: canonical_recovery_capsule_hash(&self.capsule)
                .map_err(|error| anyhow!(error))?,
            share_commitment_hash: self.share_commitment_hash,
        })
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExperimentalMultiWitnessRecoverySharePlan {
    assignment: GuardianWitnessAssignment,
    share_index: u16,
    share_count: u16,
    recovery_threshold: u16,
    share_commitment_hash: [u8; 32],
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExperimentalMultiWitnessRecoveryPlan {
    payload_commitment_hash: [u8; 32],
    recovery_committee_root_hash: [u8; 32],
    coding_root_hash: [u8; 32],
    recovery_window_close_ms: u64,
    coding: RecoveryCodingDescriptor,
    share_count: u16,
    recovery_threshold: u16,
    data_shard_count: u16,
    parity_shard_count: u16,
    shares: Vec<ExperimentalMultiWitnessRecoverySharePlan>,
}

#[derive(Clone)]
pub(super) struct GuardianRegistryPublisher {
    pub(super) workload_client: Arc<dyn WorkloadClientApi>,
    pub(super) tx_pool: Arc<Mempool>,
    pub(super) consensus_kick_tx: mpsc::UnboundedSender<()>,
    pub(super) nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
    pub(super) local_keypair: libp2p::identity::Keypair,
    pub(super) chain_id: ioi_types::app::ChainId,
}

pub(super) fn local_account_id_from_keypair(local_keypair: &libp2p::identity::Keypair) -> Result<AccountId> {
    Ok(AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &local_keypair.public().encode_protobuf(),
    )?))
}

const EXPERIMENTAL_RECOVERY_SCAFFOLD_WINDOW_MS: u64 = 60_000;
const EXPERIMENTAL_SYSTEMATIC_XOR_MIN_SHARE_COUNT: u16 = 3;
const EXPERIMENTAL_SYSTEMATIC_GF256_MIN_SHARE_COUNT: u16 = 4;
const EXPERIMENTAL_SYSTEMATIC_GF256_MIN_PARITY_SHARDS: u16 = 2;

pub(super) fn hash_experimental_recovery_scaffold_component<T: Encode>(
    domain: &'static [u8],
    value: &T,
) -> Result<[u8; 32]> {
    let bytes = encode_experimental_recovery_component(domain, value)?;
    ioi_crypto::algorithms::hash::sha256(&bytes).map_err(|e| anyhow!(e))
}

pub(super) fn encode_experimental_recovery_component<T: Encode>(
    domain: &'static [u8],
    value: &T,
) -> Result<Vec<u8>> {
    codec::to_bytes_canonical(&(domain.to_vec(), value)).map_err(|e| anyhow!(e))
}

pub(super) fn canonical_block_commitment_hash(header: &BlockHeader) -> Result<[u8; 32]> {
    let hash = header.hash().map_err(|error| anyhow!(error))?;
    hash.as_slice()
        .try_into()
        .map_err(|_| anyhow!("block header hash must be 32 bytes"))
}

pub(super) fn experimental_multi_witness_coding(
    share_count: u16,
    recovery_threshold: u16,
) -> RecoveryCodingDescriptor {
    if share_count >= EXPERIMENTAL_SYSTEMATIC_GF256_MIN_SHARE_COUNT
        && share_count
            >= recovery_threshold.saturating_add(EXPERIMENTAL_SYSTEMATIC_GF256_MIN_PARITY_SHARDS)
    {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicGf256KOfNV1,
            share_count,
            recovery_threshold,
        }
    } else if share_count >= EXPERIMENTAL_SYSTEMATIC_XOR_MIN_SHARE_COUNT
        && share_count == recovery_threshold.saturating_add(1)
    {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicXorKOfKPlus1V1,
            share_count,
            recovery_threshold,
        }
    } else {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::TransparentCommittedSurfaceV1,
            share_count,
            recovery_threshold,
        }
    }
}

pub(super) fn experimental_multi_witness_parity_threshold(share_count: u16) -> Option<u16> {
    (share_count >= EXPERIMENTAL_SYSTEMATIC_XOR_MIN_SHARE_COUNT).then_some(share_count - 1)
}

pub(super) fn experimental_multi_witness_parity_threshold_for_len(share_count: usize) -> Option<u16> {
    u16::try_from(share_count)
        .ok()
        .and_then(experimental_multi_witness_parity_threshold)
}

pub(super) fn ordered_transaction_bytes(transactions: &[ChainTransaction]) -> Result<Vec<Vec<u8>>> {
    transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).map_err(|error| anyhow!(error)))
        .collect()
}

pub(super) fn build_recoverable_slot_payload_v3_publication_bundle_bytes(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<Vec<u8>> {
    let mut publication_header = header.clone();
    publication_header.canonical_order_certificate = Some(certificate.clone());
    let execution_object =
        derive_canonical_order_execution_object(&publication_header, transactions).map_err(
            |abort| {
                anyhow!(
                    "failed to derive recoverable publication bundle: {}",
                    abort.details
                )
            },
        )?;
    let publication_bundle = build_canonical_order_publication_bundle(&execution_object);
    codec::to_bytes_canonical(&publication_bundle).map_err(|error| anyhow!(error))
}

pub(super) fn build_recoverable_slot_payload_v3(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<RecoverableSlotPayloadV3> {
    Ok(RecoverableSlotPayloadV3 {
        height: header.height,
        view: header.view,
        producer_account_id: header.producer_account_id,
        block_commitment_hash: canonical_block_commitment_hash(header)?,
        parent_block_hash: header.parent_hash,
        canonical_order_certificate: certificate.clone(),
        ordered_transaction_bytes: ordered_transaction_bytes(transactions)?,
        canonical_order_publication_bundle_bytes:
            build_recoverable_slot_payload_v3_publication_bundle_bytes(
                header,
                transactions,
                certificate,
            )?,
    })
}

pub(super) fn build_recoverable_slot_payload_v4(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<ioi_types::app::RecoverableSlotPayloadV4> {
    let payload_v3 = build_recoverable_slot_payload_v3(header, transactions, certificate)?;
    let (payload_v4, _, _) = ioi_types::app::lift_recoverable_slot_payload_v3_to_v4(&payload_v3)
        .map_err(|error| anyhow!(error))?;
    Ok(payload_v4)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_recoverable_slot_payload_v5(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<RecoverableSlotPayloadV5> {
    let payload_v4 = build_recoverable_slot_payload_v4(header, transactions, certificate)?;
    let (payload_v5, _, _, _) = ioi_types::app::lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
        .map_err(|error| anyhow!(error))?;
    Ok(payload_v5)
}

pub(super) fn recovery_coding_uses_recoverable_payload(coding: RecoveryCodingDescriptor) -> bool {
    coding
        .family_contract()
        .map(|contract| contract.uses_recoverable_payload())
        .unwrap_or(false)
}

pub(super) fn encode_coded_recovery_shards(
    coding: RecoveryCodingDescriptor,
    payload_bytes: &[u8],
) -> Result<Vec<Vec<u8>>> {
    ioi_types::app::encode_coded_recovery_shards(coding, payload_bytes)
        .map_err(|error| anyhow!(error))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn recover_recoverable_slot_payload_v3_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<RecoverableSlotPayloadV3> {
    ioi_types::app::recover_recoverable_slot_payload_v3_from_share_materials(materials)
        .map_err(|error| anyhow!(error))
}

pub(super) fn build_experimental_transparent_share_material_bytes(
    plan: &ExperimentalMultiWitnessRecoveryPlan,
    share: &ExperimentalMultiWitnessRecoverySharePlan,
    certificate: &ioi_types::app::CanonicalOrderCertificate,
) -> Result<Vec<u8>> {
    encode_experimental_recovery_component(
        b"aft::recovery::multi_witness::share_commitment::v1",
        &(
            plan.coding_root_hash,
            &share.assignment,
            share.share_index,
            share.share_count,
            share.recovery_threshold,
            plan.payload_commitment_hash,
            certificate.bulletin_commitment.bulletin_root,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
        ),
    )
}

pub(super) fn build_experimental_coded_share_commitment_hash(
    plan: &ExperimentalMultiWitnessRecoveryPlan,
    assignment: &GuardianWitnessAssignment,
    share_index: u16,
    shard_bytes: &[u8],
    coding: RecoveryCodingDescriptor,
) -> Result<[u8; 32]> {
    let domain = coding
        .family_contract()
        .map_err(|error| anyhow!(error))?
        .coded_share_commitment_domain()
        .map_err(|error| anyhow!(error))?;
    hash_experimental_recovery_scaffold_component(
        domain,
        &(
            plan.coding_root_hash,
            assignment,
            share_index,
            coding.share_count,
            coding.recovery_threshold,
            plan.payload_commitment_hash,
            shard_bytes,
        ),
    )
}

pub(super) fn build_experimental_multi_witness_share_commitment_hash(
    plan: &ExperimentalMultiWitnessRecoveryPlan,
    assignment: &GuardianWitnessAssignment,
    share_index: u16,
    coding: RecoveryCodingDescriptor,
    certificate: &ioi_types::app::CanonicalOrderCertificate,
    coded_shards: Option<&Vec<Vec<u8>>>,
) -> Result<[u8; 32]> {
    let contract = coding.family_contract().map_err(|error| anyhow!(error))?;
    if contract.uses_recoverable_payload() {
        let shard_bytes = coded_shards
            .ok_or_else(|| anyhow!("coded recovery shards were not initialized"))?
            .get(usize::from(share_index))
            .ok_or_else(|| anyhow!("coded recovery share index exceeds shard set"))?;
        build_experimental_coded_share_commitment_hash(
            plan,
            assignment,
            share_index,
            shard_bytes,
            coding,
        )
    } else if coding.is_transparent_committed_surface() {
        hash_experimental_recovery_scaffold_component(
            b"aft::recovery::multi_witness::share_commitment::v1",
            &(
                plan.coding_root_hash,
                assignment,
                share_index,
                plan.share_count,
                plan.recovery_threshold,
                plan.payload_commitment_hash,
                certificate.bulletin_commitment.bulletin_root,
                certificate.ordered_transactions_root_hash,
                certificate.resulting_state_root_hash,
            ),
        )
    } else {
        Err(anyhow!(
            "multi-witness recovery plan does not support deterministic scaffold coding"
        ))
    }
}

pub(super) fn materialize_experimental_multi_witness_share_material_bytes(
    plan: &ExperimentalMultiWitnessRecoveryPlan,
    share: &ExperimentalMultiWitnessRecoverySharePlan,
    certificate: &ioi_types::app::CanonicalOrderCertificate,
    coded_shards: Option<&Vec<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let contract = plan
        .coding
        .family_contract()
        .map_err(|error| anyhow!(error))?;
    if contract.uses_recoverable_payload() {
        coded_shards
            .ok_or_else(|| anyhow!("coded recovery shards were not initialized"))?
            .get(usize::from(share.share_index))
            .cloned()
            .ok_or_else(|| anyhow!("coded recovery share index exceeds shard set"))
    } else if plan.coding.is_transparent_committed_surface() {
        build_experimental_transparent_share_material_bytes(plan, share, certificate)
    } else {
        Err(anyhow!(
            "multi-witness recovery share materialization does not support deterministic scaffolds"
        ))
    }
}

pub(super) fn materialize_experimental_multi_witness_recovery_share_materials_from_plan(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    plan: &ExperimentalMultiWitnessRecoveryPlan,
) -> Result<Vec<RecoveryShareMaterial>> {
    let certificate = build_committed_surface_canonical_order_certificate(header, transactions)
        .map_err(|error| anyhow!(error))?;
    let block_commitment_hash = canonical_block_commitment_hash(header)?;
    let recoverable_payload = recovery_coding_uses_recoverable_payload(plan.coding)
        .then(|| build_recoverable_slot_payload_v3(header, transactions, &certificate))
        .transpose()?;
    let coded_shards = recoverable_payload
        .as_ref()
        .map(codec::to_bytes_canonical)
        .transpose()
        .map_err(|error| anyhow!(error))?
        .map(|payload_bytes| encode_coded_recovery_shards(plan.coding, &payload_bytes))
        .transpose()?;

    plan.shares
        .iter()
        .map(|share| {
            let material_bytes = materialize_experimental_multi_witness_share_material_bytes(
                plan,
                share,
                &certificate,
                coded_shards.as_ref(),
            )?;
            Ok(RecoveryShareMaterial {
                height: header.height,
                witness_manifest_hash: share.assignment.manifest_hash,
                block_commitment_hash,
                coding: plan.coding,
                share_index: share.share_index,
                share_commitment_hash: share.share_commitment_hash,
                material_bytes,
            })
        })
        .collect()
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_experimental_multi_witness_recovery_share_materials(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    reassignment_depth: u8,
    share_count: u16,
    recovery_threshold: u16,
) -> Result<Vec<RecoveryShareMaterial>> {
    let plan = build_experimental_multi_witness_recovery_plan(
        header,
        transactions,
        witness_seed,
        witness_set,
        reassignment_depth,
        share_count,
        recovery_threshold,
    )?;
    materialize_experimental_multi_witness_recovery_share_materials_from_plan(
        header,
        transactions,
        &plan,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn verify_experimental_multi_witness_recovery_share_material(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    reassignment_depth: u8,
    material: &RecoveryShareMaterial,
) -> Result<ioi_types::app::RecoveryShareReceipt> {
    if material.height != header.height {
        return Err(anyhow!(
            "recovery share material height does not match the bound block header"
        ));
    }

    let expected_block_commitment_hash = canonical_block_commitment_hash(header)?;
    if material.block_commitment_hash != expected_block_commitment_hash {
        return Err(anyhow!(
            "recovery share material block commitment does not match the bound block header"
        ));
    }

    let expected = build_experimental_multi_witness_recovery_share_materials(
        header,
        transactions,
        witness_seed,
        witness_set,
        reassignment_depth,
        material.coding.share_count,
        material.coding.recovery_threshold,
    )?
    .into_iter()
    .find(|candidate| {
        candidate.witness_manifest_hash == material.witness_manifest_hash
            && candidate.share_index == material.share_index
    })
    .ok_or_else(|| anyhow!("recovery share material is not assigned in the deterministic plan"))?;

    if expected != *material {
        return Err(anyhow!(
            "recovery share material does not match the deterministic committed-surface materialization"
        ));
    }

    Ok(material.to_recovery_share_receipt())
}

pub(super) fn build_experimental_recovery_scaffold_artifacts(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_manifest_hash: [u8; 32],
    reassignment_depth: u8,
) -> Result<ExperimentalRecoveryScaffoldArtifacts> {
    if witness_manifest_hash == [0u8; 32] {
        return Err(anyhow!(
            "experimental recovery scaffold requires a non-zero witness manifest hash"
        ));
    }

    let certificate = build_committed_surface_canonical_order_certificate(header, transactions)
        .map_err(|error| anyhow!(error))?;
    // Reuse the committed-surface recoverability root as the shared payload seed.
    // It does not carry witness/coding semantics on its own; the scaffold layers
    // those semantics above it with witness-local commitments.
    let payload_commitment_hash = certificate
        .bulletin_availability_certificate
        .recoverability_root;
    let recovery_window_close_ms = header
        .timestamp_ms_or_legacy()
        .saturating_add(EXPERIMENTAL_RECOVERY_SCAFFOLD_WINDOW_MS);
    let recovery_committee_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::scaffold::committee_root::v1",
        &(
            header.height,
            header.view,
            witness_manifest_hash,
            reassignment_depth,
        ),
    )?;
    let coding_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::scaffold::coding_root::v1",
        &(
            payload_commitment_hash,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
            witness_manifest_hash,
            reassignment_depth,
            recovery_window_close_ms,
        ),
    )?;
    let capsule = RecoveryCapsule {
        height: header.height,
        coding: RecoveryCodingDescriptor::deterministic_scaffold(),
        recovery_committee_root_hash,
        payload_commitment_hash,
        coding_root_hash,
        recovery_window_close_ms,
    };
    let share_commitment_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::scaffold::share_commitment::v1",
        &(
            canonical_recovery_capsule_hash(&capsule).map_err(|error| anyhow!(error))?,
            witness_manifest_hash,
            reassignment_depth,
            header.producer_account_id,
            certificate.bulletin_commitment.bulletin_root,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
        ),
    )?;

    Ok(ExperimentalRecoveryScaffoldArtifacts {
        capsule,
        share_commitment_hash,
    })
}

pub(super) fn build_experimental_recovery_scaffold_share_receipt(
    header: &BlockHeader,
    certificate: &ioi_types::app::RecoveryWitnessCertificate,
) -> Result<RecoveryShareReceipt> {
    build_recovery_share_receipt_for_header(header, certificate)
}

pub(super) fn build_recovery_share_receipt_for_header(
    header: &BlockHeader,
    certificate: &ioi_types::app::RecoveryWitnessCertificate,
) -> Result<RecoveryShareReceipt> {
    if certificate.height != header.height {
        return Err(anyhow!(
            "recovery witness certificate height does not match the bound block header"
        ));
    }

    Ok(RecoveryShareReceipt {
        height: header.height,
        witness_manifest_hash: certificate.witness_manifest_hash,
        block_commitment_hash: canonical_block_commitment_hash(header)?,
        share_commitment_hash: certificate.share_commitment_hash,
    })
}

pub(super) fn build_experimental_multi_witness_recovery_plan_from_assignments(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_epoch: u64,
    assignments: Vec<GuardianWitnessAssignment>,
    reassignment_depth: u8,
    recovery_threshold: u16,
) -> Result<ExperimentalMultiWitnessRecoveryPlan> {
    let share_count = u16::try_from(assignments.len())
        .map_err(|_| anyhow!("experimental multi-witness recovery plan exceeds u16 shares"))?;
    if share_count < 2 {
        return Err(anyhow!(
            "experimental multi-witness recovery plan requires at least two assigned witnesses"
        ));
    }
    if recovery_threshold < 2 {
        return Err(anyhow!(
            "experimental multi-witness recovery plan requires threshold at least two"
        ));
    }
    if recovery_threshold > share_count {
        return Err(anyhow!(
            "experimental multi-witness recovery threshold cannot exceed share count"
        ));
    }

    let certificate = build_committed_surface_canonical_order_certificate(header, transactions)
        .map_err(|error| anyhow!(error))?;
    let payload_commitment_hash = certificate
        .bulletin_availability_certificate
        .recoverability_root;
    let coding = experimental_multi_witness_coding(share_count, recovery_threshold);
    let recovery_window_close_ms = header
        .timestamp_ms_or_legacy()
        .saturating_add(EXPERIMENTAL_RECOVERY_SCAFFOLD_WINDOW_MS);
    let assigned_manifest_hashes = assignments
        .iter()
        .map(|assignment| assignment.manifest_hash)
        .collect::<Vec<_>>();
    let recovery_committee_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::multi_witness::committee_root::v1",
        &(
            witness_epoch,
            header.height,
            header.view,
            reassignment_depth,
            share_count,
            recovery_threshold,
            assigned_manifest_hashes,
        ),
    )?;
    let coding_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::multi_witness::coding_root::v1",
        &(
            payload_commitment_hash,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
            recovery_committee_root_hash,
            coding,
            share_count,
            recovery_threshold,
            recovery_window_close_ms,
        ),
    )?;
    let recoverable_payload = recovery_coding_uses_recoverable_payload(coding)
        .then(|| build_recoverable_slot_payload_v3(header, transactions, &certificate))
        .transpose()?;
    let coded_shards = recoverable_payload
        .as_ref()
        .map(codec::to_bytes_canonical)
        .transpose()
        .map_err(|error| anyhow!(error))?
        .map(|payload_bytes| encode_coded_recovery_shards(coding, &payload_bytes))
        .transpose()?;
    let plan_stub = ExperimentalMultiWitnessRecoveryPlan {
        payload_commitment_hash,
        recovery_committee_root_hash,
        coding_root_hash,
        recovery_window_close_ms,
        coding,
        share_count,
        recovery_threshold,
        data_shard_count: recovery_threshold,
        parity_shard_count: share_count.saturating_sub(recovery_threshold),
        shares: Vec::new(),
    };
    let shares = assignments
        .into_iter()
        .enumerate()
        .map(|(share_index, assignment)| {
            let share_index = u16::try_from(share_index)
                .map_err(|_| anyhow!("multi-witness share index exceeds u16"))?;
            let share_commitment_hash = build_experimental_multi_witness_share_commitment_hash(
                &plan_stub,
                &assignment,
                share_index,
                coding,
                &certificate,
                coded_shards.as_ref(),
            )?;
            Ok(ExperimentalMultiWitnessRecoverySharePlan {
                assignment,
                share_index,
                share_count,
                recovery_threshold,
                share_commitment_hash,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let data_shard_count = recovery_threshold;
    let parity_shard_count = share_count.saturating_sub(recovery_threshold);

    Ok(ExperimentalMultiWitnessRecoveryPlan {
        payload_commitment_hash,
        recovery_committee_root_hash,
        coding_root_hash,
        recovery_window_close_ms,
        coding,
        share_count,
        recovery_threshold,
        data_shard_count,
        parity_shard_count,
        shares,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_experimental_multi_witness_recovery_plan(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    witness_seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    reassignment_depth: u8,
    share_count: u16,
    recovery_threshold: u16,
) -> Result<ExperimentalMultiWitnessRecoveryPlan> {
    if share_count < 2 {
        return Err(anyhow!(
            "experimental multi-witness recovery plan requires at least two assigned witnesses"
        ));
    }
    if recovery_threshold < 2 {
        return Err(anyhow!(
            "experimental multi-witness recovery plan requires threshold at least two"
        ));
    }
    if recovery_threshold > share_count {
        return Err(anyhow!(
            "experimental multi-witness recovery threshold cannot exceed share count"
        ));
    }

    let certificate = build_committed_surface_canonical_order_certificate(header, transactions)
        .map_err(|error| anyhow!(error))?;
    let assignments = derive_guardian_witness_assignments(
        witness_seed,
        witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        reassignment_depth,
        share_count,
    )
    .map_err(|error| anyhow!(error))?;
    let payload_commitment_hash = certificate
        .bulletin_availability_certificate
        .recoverability_root;
    let coding = experimental_multi_witness_coding(share_count, recovery_threshold);
    let recovery_window_close_ms = header
        .timestamp_ms_or_legacy()
        .saturating_add(EXPERIMENTAL_RECOVERY_SCAFFOLD_WINDOW_MS);
    let assigned_manifest_hashes = assignments
        .iter()
        .map(|assignment| assignment.manifest_hash)
        .collect::<Vec<_>>();
    let recovery_committee_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::multi_witness::committee_root::v1",
        &(
            witness_seed.epoch,
            header.height,
            header.view,
            reassignment_depth,
            share_count,
            recovery_threshold,
            assigned_manifest_hashes,
        ),
    )?;
    let coding_root_hash = hash_experimental_recovery_scaffold_component(
        b"aft::recovery::multi_witness::coding_root::v1",
        &(
            payload_commitment_hash,
            certificate.ordered_transactions_root_hash,
            certificate.resulting_state_root_hash,
            recovery_committee_root_hash,
            coding,
            share_count,
            recovery_threshold,
            recovery_window_close_ms,
        ),
    )?;
    let recoverable_payload = recovery_coding_uses_recoverable_payload(coding)
        .then(|| build_recoverable_slot_payload_v3(header, transactions, &certificate))
        .transpose()?;
    let coded_shards = recoverable_payload
        .as_ref()
        .map(codec::to_bytes_canonical)
        .transpose()
        .map_err(|error| anyhow!(error))?
        .map(|payload_bytes| encode_coded_recovery_shards(coding, &payload_bytes))
        .transpose()?;
    let plan_stub = ExperimentalMultiWitnessRecoveryPlan {
        payload_commitment_hash,
        recovery_committee_root_hash,
        coding_root_hash,
        recovery_window_close_ms,
        coding,
        share_count,
        recovery_threshold,
        data_shard_count: recovery_threshold,
        parity_shard_count: share_count.saturating_sub(recovery_threshold),
        shares: Vec::new(),
    };
    let shares = assignments
        .into_iter()
        .enumerate()
        .map(|(share_index, assignment)| {
            let share_index = u16::try_from(share_index)
                .map_err(|_| anyhow!("multi-witness share index exceeds u16"))?;
            let share_commitment_hash = build_experimental_multi_witness_share_commitment_hash(
                &plan_stub,
                &assignment,
                share_index,
                coding,
                &certificate,
                coded_shards.as_ref(),
            )?;
            Ok(ExperimentalMultiWitnessRecoverySharePlan {
                assignment,
                share_index,
                share_count,
                recovery_threshold,
                share_commitment_hash,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let data_shard_count = recovery_threshold;
    let parity_shard_count = share_count.saturating_sub(recovery_threshold);

    Ok(ExperimentalMultiWitnessRecoveryPlan {
        payload_commitment_hash,
        recovery_committee_root_hash,
        coding_root_hash,
        recovery_window_close_ms,
        coding,
        share_count,
        recovery_threshold,
        data_shard_count,
        parity_shard_count,
        shares,
    })
}

pub(super) fn build_experimental_multi_witness_recovery_capsule(
    height: u64,
    plan: &ExperimentalMultiWitnessRecoveryPlan,
) -> Result<RecoveryCapsule> {
    if plan.coding.is_transparent_committed_surface() {
        return Err(anyhow!(
            "multi-witness recovery capsule requires a non-trivial coded lane"
        ));
    }
    if plan.coding.is_deterministic_scaffold() {
        return Err(anyhow!(
            "multi-witness recovery capsule requires a non-trivial coded lane"
        ));
    }

    Ok(RecoveryCapsule {
        height,
        coding: plan.coding,
        recovery_committee_root_hash: plan.recovery_committee_root_hash,
        payload_commitment_hash: plan.payload_commitment_hash,
        coding_root_hash: plan.coding_root_hash,
        recovery_window_close_ms: plan.recovery_window_close_ms,
    })
}

pub(super) fn build_experimental_multi_witness_recovery_binding_assignments(
    height: u64,
    plan: &ExperimentalMultiWitnessRecoveryPlan,
) -> Result<(
    RecoveryCapsule,
    Vec<ioi_types::app::GuardianWitnessRecoveryBindingAssignment>,
)> {
    let capsule = build_experimental_multi_witness_recovery_capsule(height, plan)?;
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).map_err(|e| anyhow!(e))?;
    let assignments = plan
        .shares
        .iter()
        .map(
            |share| ioi_types::app::GuardianWitnessRecoveryBindingAssignment {
                witness_manifest_hash: share.assignment.manifest_hash,
                recovery_binding: GuardianWitnessRecoveryBinding {
                    recovery_capsule_hash,
                    share_commitment_hash: share.share_commitment_hash,
                },
            },
        )
        .collect();
    Ok((capsule, assignments))
}

pub(super) fn build_assigned_recovery_share_envelopes(
    capsule: &RecoveryCapsule,
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<AssignedRecoveryShareEnvelopeV1>> {
    let recovery_capsule_hash = canonical_recovery_capsule_hash(capsule).map_err(|e| anyhow!(e))?;
    Ok(materials
        .iter()
        .cloned()
        .map(|share_material| AssignedRecoveryShareEnvelopeV1 {
            recovery_capsule_hash,
            expected_share_commitment_hash: share_material.share_commitment_hash,
            share_material,
        })
        .collect())
}

pub(super) fn build_invalid_canonical_close_challenge(
    header: &BlockHeader,
    proof: &SealedFinalityProof,
    challenger_account_id: AccountId,
    assignment: Option<ioi_types::app::AsymptoteObserverAssignment>,
    canonical_close: &AsymptoteObserverCanonicalClose,
    details: impl Into<String>,
) -> Result<AsymptoteObserverChallenge> {
    let mut challenge = AsymptoteObserverChallenge {
        challenge_id: [0u8; 32],
        epoch: proof.epoch,
        height: header.height,
        view: header.view,
        kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
        challenger_account_id,
        assignment,
        observation_request: None,
        transcript: None,
        canonical_close: Some(canonical_close.clone()),
        evidence_hash: canonical_asymptote_observer_canonical_close_hash(canonical_close)
            .map_err(anyhow::Error::msg)?,
        details: details.into(),
    };
    challenge.challenge_id = ioi_crypto::algorithms::hash::sha256(
        &codec::to_bytes_canonical(&challenge).map_err(|e| anyhow!(e))?,
    )?;
    Ok(challenge)
}

pub(super) fn invalid_canonical_close_details(
    header: &BlockHeader,
    proof: &SealedFinalityProof,
    assignments_hash: [u8; 32],
    transcript_commitment: &AsymptoteObserverTranscriptCommitment,
    challenge_commitment: &AsymptoteObserverChallengeCommitment,
    canonical_close: &AsymptoteObserverCanonicalClose,
    transcripts_root: [u8; 32],
    challenges_root: [u8; 32],
    transcript_count: u16,
    challenge_count: u16,
) -> Option<String> {
    if proof.finality_tier != ioi_types::app::FinalityTier::SealedFinal
        || proof.collapse_state != ioi_types::app::CollapseState::SealedFinal
    {
        return Some("canonical observer close was carried on a non-SealedFinal proof path".into());
    }
    if transcript_commitment.epoch != proof.epoch
        || transcript_commitment.height != header.height
        || transcript_commitment.view != header.view
    {
        return Some("observer transcript commitment does not bind the sealed slot".into());
    }
    if transcript_commitment.assignments_hash != assignments_hash {
        return Some(
            "observer transcript commitment assignments hash does not match the deterministic observer surface"
                .into(),
        );
    }
    if transcript_commitment.transcripts_root != transcripts_root {
        return Some(
            "observer transcript commitment does not match the canonical transcript surface".into(),
        );
    }
    if transcript_commitment.transcript_count != transcript_count {
        return Some(
            "observer transcript commitment count does not match the canonical transcript surface"
                .into(),
        );
    }
    if challenge_commitment.epoch != proof.epoch
        || challenge_commitment.height != header.height
        || challenge_commitment.view != header.view
    {
        return Some("observer challenge commitment does not bind the sealed slot".into());
    }
    if challenge_commitment.challenges_root != challenges_root {
        return Some(
            "observer challenge commitment does not match the canonical challenge surface".into(),
        );
    }
    if challenge_commitment.challenge_count != challenge_count {
        return Some(
            "observer challenge commitment count does not match the canonical challenge surface"
                .into(),
        );
    }
    if canonical_close.epoch != proof.epoch
        || canonical_close.height != header.height
        || canonical_close.view != header.view
    {
        return Some("canonical observer close does not bind the sealed slot".into());
    }
    if canonical_close.assignments_hash != assignments_hash {
        return Some(
            "canonical observer close assignments hash does not match the deterministic observer surface"
                .into(),
        );
    }
    if canonical_close.transcripts_root != transcripts_root {
        return Some(
            "canonical observer close does not match the canonical transcript surface".into(),
        );
    }
    if canonical_close.challenges_root != challenges_root {
        return Some(
            "canonical observer close does not match the canonical challenge surface".into(),
        );
    }
    if canonical_close.transcript_count != transcript_count {
        return Some(
            "canonical observer close transcript count does not match the canonical transcript surface"
                .into(),
        );
    }
    if canonical_close.challenge_count != challenge_count {
        return Some(
            "canonical observer close challenge count does not match the canonical challenge surface"
                .into(),
        );
    }
    if !proof.observer_challenges.is_empty() || challenge_count != 0 {
        return Some(
            "canonical observer close is challenge-dominated by a non-empty challenge surface"
                .into(),
        );
    }
    if canonical_close.challenge_cutoff_timestamp_ms == 0 {
        return Some("canonical observer close must carry a non-zero challenge cutoff".into());
    }
    None
}

pub(super) fn decode_state_value<T: parity_scale_codec::Decode>(bytes: &[u8]) -> Result<T> {
    if let Ok(value) = codec::from_bytes_canonical::<T>(bytes) {
        return Ok(value);
    }
    let entry: StateEntry = codec::from_bytes_canonical(bytes)
        .map_err(|e| anyhow!("failed to decode StateEntry wrapper: {e}"))?;
    codec::from_bytes_canonical(&entry.value)
        .map_err(|e| anyhow!("failed to decode wrapped state value: {e}"))
}

pub(super) fn decode_account_nonce(bytes: &[u8]) -> u64 {
    if let Ok(value) = decode_state_value::<u64>(bytes) {
        return value;
    }
    if bytes.len() == 8 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        return u64::from_le_bytes(raw);
    }
    0
}

pub(super) async fn reserve_nonce_for_account(
    workload_client: &Arc<dyn WorkloadClientApi>,
    nonce_manager: &Arc<Mutex<BTreeMap<AccountId, u64>>>,
    account_id: AccountId,
) -> u64 {
    let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
    let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
        Ok(Some(bytes)) => decode_account_nonce(&bytes),
        _ => 0,
    };

    let mut guard = nonce_manager.lock().await;
    let entry = guard.entry(account_id).or_insert(state_nonce);
    if *entry < state_nonce {
        *entry = state_nonce;
    }
    let nonce = *entry;
    *entry = entry.saturating_add(1);
    nonce
}

impl GuardianRegistryPublisher {
    pub(super) async fn from_context<CS, ST, CE, V>(
        context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    ) -> Self
    where
        CS: CommitmentScheme + Clone + Send + Sync + 'static,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send
            + Sync
            + 'static
            + Debug
            + Clone,
        CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
        V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
            + Clone
            + Send
            + Sync
            + 'static
            + Debug,
        <CS as CommitmentScheme>::Proof: Serialize
            + for<'de> serde::Deserialize<'de>
            + Clone
            + Send
            + Sync
            + 'static
            + Debug
            + Encode
            + Decode,
        <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    {
        let ctx = context_arc.lock().await;
        Self {
            workload_client: ctx.view_resolver.workload_client().clone(),
            tx_pool: ctx.tx_pool_ref.clone(),
            consensus_kick_tx: ctx.consensus_kick_tx.clone(),
            nonce_manager: ctx.nonce_manager.clone(),
            local_keypair: ctx.local_keypair.clone(),
            chain_id: ctx.chain_id,
        }
    }

    pub(super) async fn enqueue_call(&self, method: &str, params: Vec<u8>) -> Result<()> {
        let public_key = self.local_keypair.public().encode_protobuf();
        let account_id = AccountId(account_id_from_key_material(
            SignatureSuite::ED25519,
            &public_key,
        )?);
        let nonce =
            reserve_nonce_for_account(&self.workload_client, &self.nonce_manager, account_id).await;
        let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
        let committed_nonce = match self.workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(bytes)) => decode_account_nonce(&bytes),
            _ => 0,
        };

        let payload = SystemPayload::CallService {
            service_id: "guardian_registry".to_string(),
            method: method.to_string(),
            params,
        };
        let mut sys_tx = SystemTransaction {
            header: SignHeader {
                account_id,
                nonce,
                chain_id: self.chain_id,
                tx_version: 1,
                session_auth: None,
            },
            payload,
            signature_proof: SignatureProof::default(),
        };
        let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
        let signature = self.local_keypair.sign(&sign_bytes)?;
        sys_tx.signature_proof = SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key,
            signature,
        };
        let tx = ChainTransaction::System(Box::new(sys_tx));
        let tx_hash = tx.hash()?;
        match self
            .tx_pool
            .add(tx, tx_hash, Some((account_id, nonce)), committed_nonce)
        {
            AddResult::Rejected(reason) => Err(anyhow!(
                "guardian_registry publication tx rejected for {method}: {reason}"
            )),
            AddResult::Known => Ok(()),
            AddResult::Ready | AddResult::Future => {
                let _ = self.consensus_kick_tx.send(());
                Ok(())
            }
        }
    }
}

pub(super) fn build_canonical_observer_statement(
    proof: &SealedFinalityProof,
    guardian_checkpoint: Option<&GuardianLogCheckpoint>,
    assignment: &ioi_types::app::AsymptoteObserverAssignment,
    observer_certificate: &ioi_types::app::AsymptoteObserverCertificate,
    block_hash: [u8; 32],
) -> AsymptoteObserverStatement {
    AsymptoteObserverStatement {
        epoch: proof.epoch,
        assignment: assignment.clone(),
        block_hash,
        guardian_manifest_hash: proof.guardian_manifest_hash,
        guardian_decision_hash: proof.guardian_decision_hash,
        guardian_counter: proof.guardian_counter,
        guardian_trace_hash: proof.guardian_trace_hash,
        guardian_measurement_root: proof.guardian_measurement_root,
        guardian_checkpoint_root: guardian_checkpoint
            .map(|checkpoint| checkpoint.root_hash)
            .unwrap_or([0u8; 32]),
        verdict: observer_certificate.verdict,
        veto_kind: observer_certificate.veto_kind,
        evidence_hash: observer_certificate.evidence_hash,
    }
}

pub(super) fn canonicalize_observer_sealed_finality_proof(
    header: &ioi_types::app::BlockHeader,
    policy: &AsymptotePolicy,
    block_hash: [u8; 32],
    proof: &mut SealedFinalityProof,
) -> Result<Option<CanonicalObserverPublicationArtifacts>> {
    if policy.observer_sealing_mode != AsymptoteObserverSealingMode::CanonicalChallengeV1 {
        return Ok(None);
    }
    if policy.observer_challenge_window_ms == 0 {
        return Err(anyhow!(
            "canonical observer sealing requires a non-zero challenge window"
        ));
    }
    if proof.observer_transcript_commitment.is_some()
        || proof.observer_challenge_commitment.is_some()
        || proof.observer_canonical_close.is_some()
        || proof.observer_canonical_abort.is_some()
    {
        if proof.observer_transcript_commitment.is_none()
            || proof.observer_challenge_commitment.is_none()
        {
            return Err(anyhow!(
                "canonical observer sealing proof is missing one of its observer commitments"
            ));
        }
        if proof.observer_canonical_close.is_some() == proof.observer_canonical_abort.is_some() {
            return Err(anyhow!(
                "canonical observer sealing proof must carry exactly one of canonical close or canonical abort"
            ));
        }
        if let Some(canonical_close) = proof.observer_canonical_close.clone() {
            let transcripts_root =
                canonical_asymptote_observer_transcripts_hash(&proof.observer_transcripts)
                    .map_err(|e| anyhow!(e))?;
            let transcript_count = u16::try_from(proof.observer_transcripts.len())
                .map_err(|_| anyhow!("observer transcript count exceeds u16"))?;
            let challenges_root =
                canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)
                    .map_err(|e| anyhow!(e))?;
            let challenge_count = u16::try_from(proof.observer_challenges.len())
                .map_err(|_| anyhow!("observer challenge count exceeds u16"))?;
            let assignments_hash = proof
                .observer_transcript_commitment
                .as_ref()
                .expect("checked above")
                .assignments_hash;
            let transcript_commitment = proof
                .observer_transcript_commitment
                .as_ref()
                .expect("checked above");
            let challenge_commitment = proof
                .observer_challenge_commitment
                .as_ref()
                .expect("checked above");
            if let Some(details) = invalid_canonical_close_details(
                header,
                proof,
                assignments_hash,
                transcript_commitment,
                challenge_commitment,
                &canonical_close,
                transcripts_root,
                challenges_root,
                transcript_count,
                challenge_count,
            ) {
                let invalid_close_challenge = build_invalid_canonical_close_challenge(
                    header,
                    proof,
                    header.producer_account_id,
                    None,
                    &canonical_close,
                    details,
                )?;
                if !proof.observer_challenges.iter().any(|existing| {
                    existing.kind == AsymptoteObserverChallengeKind::InvalidCanonicalClose
                        && existing.evidence_hash == invalid_close_challenge.evidence_hash
                }) {
                    proof.observer_challenges.push(invalid_close_challenge);
                }
                let challenges_root =
                    canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)
                        .map_err(|e| anyhow!(e))?;
                let challenge_count = u16::try_from(proof.observer_challenges.len())
                    .map_err(|_| anyhow!("observer challenge count exceeds u16"))?;
                let transcript_commitment = AsymptoteObserverTranscriptCommitment {
                    epoch: proof.epoch,
                    height: header.height,
                    view: header.view,
                    assignments_hash,
                    transcripts_root,
                    transcript_count,
                };
                let challenge_commitment = AsymptoteObserverChallengeCommitment {
                    epoch: proof.epoch,
                    height: header.height,
                    view: header.view,
                    challenges_root,
                    challenge_count,
                };
                let canonical_abort = AsymptoteObserverCanonicalAbort {
                    epoch: proof.epoch,
                    height: header.height,
                    view: header.view,
                    assignments_hash,
                    transcripts_root,
                    challenges_root,
                    transcript_count,
                    challenge_count,
                    challenge_cutoff_timestamp_ms: header
                        .timestamp_ms_or_legacy()
                        .saturating_add(policy.observer_challenge_window_ms),
                };
                proof.finality_tier = ioi_types::app::FinalityTier::BaseFinal;
                proof.collapse_state = ioi_types::app::CollapseState::Abort;
                proof.observer_transcript_commitment = Some(transcript_commitment.clone());
                proof.observer_challenge_commitment = Some(challenge_commitment.clone());
                proof.observer_canonical_close = None;
                proof.observer_canonical_abort = Some(canonical_abort.clone());
                return Ok(Some(CanonicalObserverPublicationArtifacts {
                    transcripts: proof.observer_transcripts.clone(),
                    challenges: proof.observer_challenges.clone(),
                    transcript_commitment,
                    challenge_commitment,
                    canonical_close: None,
                    canonical_abort: Some(canonical_abort),
                }));
            }
        }
        return Ok(Some(CanonicalObserverPublicationArtifacts {
            transcripts: proof.observer_transcripts.clone(),
            challenges: proof.observer_challenges.clone(),
            transcript_commitment: proof
                .observer_transcript_commitment
                .clone()
                .expect("checked above"),
            challenge_commitment: proof
                .observer_challenge_commitment
                .clone()
                .expect("checked above"),
            canonical_close: proof.observer_canonical_close.clone(),
            canonical_abort: proof.observer_canonical_abort.clone(),
        }));
    }
    if proof.observer_certificates.is_empty() {
        return Ok(None);
    }
    if !proof.veto_proofs.is_empty() {
        return Err(anyhow!(
            "canonical observer sealing cannot convert veto proofs into SealedFinal transcripts"
        ));
    }

    let assignments = proof
        .observer_certificates
        .iter()
        .map(|certificate| certificate.assignment.clone())
        .collect::<Vec<_>>();
    let assignments_hash =
        canonical_asymptote_observer_assignments_hash(&assignments).map_err(|e| anyhow!(e))?;
    if let Some(observer_close_certificate) = proof.observer_close_certificate.as_ref() {
        if observer_close_certificate.assignments_hash != assignments_hash {
            return Err(anyhow!(
                "observer close certificate assignments hash does not match observer certificates"
            ));
        }
    }

    let guardian_checkpoint = header
        .guardian_certificate
        .as_ref()
        .and_then(|certificate| certificate.log_checkpoint.as_ref());
    let transcripts = proof
        .observer_certificates
        .iter()
        .map(|observer_certificate| AsymptoteObserverTranscript {
            statement: build_canonical_observer_statement(
                proof,
                guardian_checkpoint,
                &observer_certificate.assignment,
                observer_certificate,
                block_hash,
            ),
            guardian_certificate: observer_certificate.guardian_certificate.clone(),
        })
        .collect::<Vec<_>>();
    let challenges = Vec::new();
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&transcripts).map_err(|e| anyhow!(e))?;
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&challenges).map_err(|e| anyhow!(e))?;
    let transcript_count = u16::try_from(transcripts.len())
        .map_err(|_| anyhow!("observer transcript count exceeds u16"))?;
    let challenge_count = u16::try_from(challenges.len())
        .map_err(|_| anyhow!("observer challenge count exceeds u16"))?;
    let challenge_cutoff_timestamp_ms = header
        .timestamp_ms_or_legacy()
        .saturating_add(policy.observer_challenge_window_ms);

    let artifacts = CanonicalObserverPublicationArtifacts {
        transcripts: transcripts.clone(),
        challenges: challenges.clone(),
        transcript_commitment: AsymptoteObserverTranscriptCommitment {
            epoch: proof.epoch,
            height: header.height,
            view: header.view,
            assignments_hash,
            transcripts_root,
            transcript_count,
        },
        challenge_commitment: AsymptoteObserverChallengeCommitment {
            epoch: proof.epoch,
            height: header.height,
            view: header.view,
            challenges_root,
            challenge_count,
        },
        canonical_close: Some(AsymptoteObserverCanonicalClose {
            epoch: proof.epoch,
            height: header.height,
            view: header.view,
            assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count,
            challenge_count,
            challenge_cutoff_timestamp_ms,
        }),
        canonical_abort: None,
    };

    proof.observer_transcripts = artifacts.transcripts.clone();
    proof.observer_challenges = artifacts.challenges.clone();
    proof.observer_transcript_commitment = Some(artifacts.transcript_commitment.clone());
    proof.observer_challenge_commitment = Some(artifacts.challenge_commitment.clone());
    proof.observer_canonical_close = artifacts.canonical_close.clone();
    proof.observer_canonical_abort = None;
    proof.observer_certificates.clear();
    proof.observer_close_certificate = None;

    Ok(Some(artifacts))
}

pub(super) fn sign_sealed_finality_proof(
    proof: &mut SealedFinalityProof,
    local_keypair: &libp2p::identity::Keypair,
) -> Result<()> {
    proof.proof_signature = SignatureProof::default();
    let sign_bytes =
        canonical_sealed_finality_proof_signing_bytes(proof).map_err(anyhow::Error::msg)?;
    proof.proof_signature = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: local_keypair.public().encode_protobuf(),
        signature: local_keypair.sign(&sign_bytes)?,
    };
    Ok(())
}

pub(super) async fn publish_canonical_observer_artifacts(
    publisher: &GuardianRegistryPublisher,
    artifacts: &CanonicalObserverPublicationArtifacts,
) -> Result<()> {
    for transcript in &artifacts.transcripts {
        publisher
            .enqueue_call(
                "publish_asymptote_observer_transcript@v1",
                codec::to_bytes_canonical(transcript).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    publisher
        .enqueue_call(
            "publish_asymptote_observer_transcript_commitment@v1",
            codec::to_bytes_canonical(&artifacts.transcript_commitment).map_err(|e| anyhow!(e))?,
        )
        .await?;
    for challenge in &artifacts.challenges {
        publisher
            .enqueue_call(
                "report_asymptote_observer_challenge@v1",
                codec::to_bytes_canonical(challenge).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    publisher
        .enqueue_call(
            "publish_asymptote_observer_challenge_commitment@v1",
            codec::to_bytes_canonical(&artifacts.challenge_commitment).map_err(|e| anyhow!(e))?,
        )
        .await?;
    if let Some(canonical_close) = artifacts.canonical_close.as_ref() {
        publisher
            .enqueue_call(
                "publish_asymptote_observer_canonical_close@v1",
                codec::to_bytes_canonical(canonical_close).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    if let Some(canonical_abort) = artifacts.canonical_abort.as_ref() {
        publisher
            .enqueue_call(
                "publish_asymptote_observer_canonical_abort@v1",
                codec::to_bytes_canonical(canonical_abort).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    Ok(())
}

pub(super) fn build_canonical_order_publication_bundle(
    execution_object: &CanonicalOrderExecutionObject,
) -> CanonicalOrderPublicationBundle {
    CanonicalOrderPublicationBundle {
        bulletin_commitment: execution_object.bulletin_commitment.clone(),
        bulletin_entries: execution_object.bulletin_entries.clone(),
        bulletin_availability_certificate: execution_object
            .bulletin_availability_certificate
            .clone(),
        bulletin_retrievability_profile: execution_object.bulletin_retrievability_profile.clone(),
        bulletin_shard_manifest: execution_object.bulletin_shard_manifest.clone(),
        bulletin_custody_receipt: execution_object.bulletin_custody_receipt.clone(),
        canonical_order_certificate: execution_object.canonical_order_certificate.clone(),
    }
}

pub(super) fn build_canonical_order_publication_artifacts(
    header: &ioi_types::app::BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalOrderPublicationArtifacts> {
    match derive_canonical_order_execution_object(header, transactions) {
        Ok(execution_object) => Ok(CanonicalOrderPublicationArtifacts {
            bundle: Some(build_canonical_order_publication_bundle(&execution_object)),
            publication_frontier: header.publication_frontier.clone(),
            canonical_abort: None,
        }),
        Err(canonical_abort) => Ok(CanonicalOrderPublicationArtifacts {
            bundle: None,
            publication_frontier: None,
            canonical_abort: Some(canonical_abort),
        }),
    }
}

pub(super) async fn publish_canonical_order_artifacts(
    publisher: &GuardianRegistryPublisher,
    artifacts: &CanonicalOrderPublicationArtifacts,
) -> Result<()> {
    if let Some(bundle) = artifacts.bundle.as_ref() {
        publisher
            .enqueue_call(
                "publish_aft_canonical_order_artifact_bundle@v1",
                codec::to_bytes_canonical(bundle).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    if let Some(frontier) = artifacts.publication_frontier.as_ref() {
        publisher
            .enqueue_call(
                "publish_aft_publication_frontier@v1",
                codec::to_bytes_canonical(frontier).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    if let Some(canonical_abort) = artifacts.canonical_abort.as_ref() {
        publisher
            .enqueue_call(
                "publish_aft_canonical_order_abort@v1",
                codec::to_bytes_canonical(canonical_abort).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }
    Ok(())
}

pub(super) async fn publish_experimental_recovery_artifacts(
    publisher: &GuardianRegistryPublisher,
    block: &Block<ChainTransaction>,
) -> Result<()> {
    let Some(guardian_certificate) = block.header.guardian_certificate.as_ref() else {
        return Ok(());
    };
    let Some(witness_certificate) = guardian_certificate
        .experimental_witness_certificate
        .as_ref()
    else {
        return Ok(());
    };
    let scaffold = build_experimental_recovery_scaffold_artifacts(
        &block.header,
        &block.transactions,
        witness_certificate.manifest_hash,
        witness_certificate.reassignment_depth,
    )?;
    let expected_binding = scaffold.recovery_binding()?;
    if witness_certificate.recovery_binding.as_ref() != Some(&expected_binding) {
        tracing::warn!(
            target: "consensus",
            height = block.header.height,
            witness_manifest_hash = %hex::encode(witness_certificate.manifest_hash),
            "Skipping recovery publication because the signed witness binding does not match the deterministic recovery scaffold."
        );
        return Ok(());
    }
    let Some(certificate) =
        derive_recovery_witness_certificate_for_header(&block.header, guardian_certificate)
            .map_err(|error| anyhow!(error))?
    else {
        return Ok(());
    };

    match publisher
        .workload_client
        .query_raw_state(&aft_recovery_capsule_key(scaffold.capsule.height))
        .await
        .map_err(|error| anyhow!("failed to query recovery capsule state: {error}"))?
    {
        Some(capsule_bytes) => {
            let existing: RecoveryCapsule = codec::from_bytes_canonical(&capsule_bytes)
                .map_err(|e| anyhow!("failed to decode recovery capsule: {e}"))?;
            if existing != scaffold.capsule {
                tracing::warn!(
                    target: "consensus",
                    height = certificate.height,
                    witness_manifest_hash = %hex::encode(certificate.witness_manifest_hash),
                    "Skipping recovery publication because a conflicting recovery capsule is already present in state."
                );
                return Ok(());
            }
        }
        None => {
            publisher
                .enqueue_call(
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(&scaffold.capsule).map_err(|e| anyhow!(e))?,
                )
                .await?;
        }
    }

    publisher
        .enqueue_call(
            "publish_aft_recovery_witness_certificate@v1",
            codec::to_bytes_canonical(&certificate).map_err(|e| anyhow!(e))?,
        )
        .await?;

    let receipt = build_recovery_share_receipt_for_header(&block.header, &certificate)?;
    if publisher
        .workload_client
        .query_raw_state(&aft_missing_recovery_share_key(
            receipt.height,
            &receipt.witness_manifest_hash,
        ))
        .await
        .map_err(|error| anyhow!("failed to query missing recovery share state: {error}"))?
        .is_some()
    {
        tracing::warn!(
            target: "consensus",
            height = receipt.height,
            witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
            "Skipping recovery share receipt publication because the witness already has an objective missing-share record."
        );
        return Ok(());
    }
    match publisher
        .workload_client
        .query_raw_state(&aft_recovery_share_receipt_key(
            receipt.height,
            &receipt.witness_manifest_hash,
            &receipt.block_commitment_hash,
        ))
        .await
        .map_err(|error| anyhow!("failed to query recovery share receipt state: {error}"))?
    {
        Some(existing_receipt_bytes) => {
            let existing: RecoveryShareReceipt =
                codec::from_bytes_canonical(&existing_receipt_bytes)
                    .map_err(|e| anyhow!("failed to decode recovery share receipt: {e}"))?;
            if existing != receipt {
                tracing::warn!(
                    target: "consensus",
                    height = receipt.height,
                    witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
                    block_commitment_hash = %hex::encode(receipt.block_commitment_hash),
                    "Skipping recovery share receipt publication because a conflicting receipt is already present in state."
                );
                return Ok(());
            }
            return Ok(());
        }
        None => {}
    }

    publisher
        .enqueue_call(
            "publish_aft_recovery_share_receipt@v1",
            codec::to_bytes_canonical(&receipt).map_err(|e| anyhow!(e))?,
        )
        .await
}

pub(super) async fn publish_experimental_sealed_recovery_artifacts(
    publisher: &GuardianRegistryPublisher,
    block: &Block<ChainTransaction>,
    expected_capsule: Option<&RecoveryCapsule>,
    expected_bindings: &[ioi_types::app::GuardianWitnessRecoveryBindingAssignment],
) -> Result<()> {
    let Some(expected_capsule) = expected_capsule else {
        return Ok(());
    };
    if expected_bindings.is_empty() {
        return Ok(());
    }

    let Some(guardian_certificate) = block.header.guardian_certificate.as_ref() else {
        return Ok(());
    };
    let Some(proof) = block.header.sealed_finality_proof.as_ref() else {
        return Ok(());
    };
    if proof.witness_certificates.is_empty() {
        return Ok(());
    }
    if proof.witness_certificates.len() != expected_bindings.len() {
        tracing::warn!(
            target: "consensus",
            height = block.header.height,
            expected_witness_count = expected_bindings.len(),
            proof_witness_count = proof.witness_certificates.len(),
            "Skipping sealed recovery publication because the returned sealed proof does not carry the expected number of witness certificates."
        );
        return Ok(());
    }

    let mut expected_bindings_by_manifest = expected_bindings
        .iter()
        .cloned()
        .map(|assignment| {
            (
                assignment.witness_manifest_hash,
                assignment.recovery_binding,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut derived_certificates = Vec::with_capacity(proof.witness_certificates.len());
    for witness_certificate in &proof.witness_certificates {
        let Some(expected_binding) =
            expected_bindings_by_manifest.remove(&witness_certificate.manifest_hash)
        else {
            tracing::warn!(
                target: "consensus",
                height = block.header.height,
                witness_manifest_hash = %hex::encode(witness_certificate.manifest_hash),
                "Skipping sealed recovery publication because the sealed proof includes an unexpected witness committee."
            );
            return Ok(());
        };
        if witness_certificate.recovery_binding.as_ref() != Some(&expected_binding) {
            tracing::warn!(
                target: "consensus",
                height = block.header.height,
                witness_manifest_hash = %hex::encode(witness_certificate.manifest_hash),
                "Skipping sealed recovery publication because the sealed proof witness binding does not match the deterministic fixed-lane recovery plan."
            );
            return Ok(());
        }

        let statement = ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
            &block.header,
            guardian_certificate,
            witness_certificate.recovery_binding.clone(),
        );
        let Some(derived_certificate) =
            ioi_types::app::derive_recovery_witness_certificate(&statement, witness_certificate)
                .map_err(|error| anyhow!(error))?
        else {
            tracing::warn!(
                target: "consensus",
                height = block.header.height,
                witness_manifest_hash = %hex::encode(witness_certificate.manifest_hash),
                "Skipping sealed recovery publication because the witness certificate did not yield a recovery witness certificate."
            );
            return Ok(());
        };
        derived_certificates.push(derived_certificate);
    }
    if !expected_bindings_by_manifest.is_empty() {
        tracing::warn!(
            target: "consensus",
            height = block.header.height,
            missing_witness_count = expected_bindings_by_manifest.len(),
            "Skipping sealed recovery publication because one or more expected witness bindings were not carried by the sealed proof."
        );
        return Ok(());
    }

    match publisher
        .workload_client
        .query_raw_state(&aft_recovery_capsule_key(expected_capsule.height))
        .await
        .map_err(|error| anyhow!("failed to query sealed recovery capsule state: {error}"))?
    {
        Some(capsule_bytes) => {
            let existing: RecoveryCapsule = codec::from_bytes_canonical(&capsule_bytes)
                .map_err(|e| anyhow!("failed to decode sealed recovery capsule: {e}"))?;
            if existing != *expected_capsule {
                tracing::warn!(
                    target: "consensus",
                    height = block.header.height,
                    "Skipping sealed recovery publication because a conflicting recovery capsule is already present in state."
                );
                return Ok(());
            }
        }
        None => {
            publisher
                .enqueue_call(
                    "publish_aft_recovery_capsule@v1",
                    codec::to_bytes_canonical(expected_capsule).map_err(|e| anyhow!(e))?,
                )
                .await?;
        }
    }

    for certificate in derived_certificates {
        let witness_manifest_hash = certificate.witness_manifest_hash;
        let certificate_key = ioi_types::app::aft_recovery_witness_certificate_key(
            certificate.height,
            &witness_manifest_hash,
        );
        let publish_certificate = match publisher
            .workload_client
            .query_raw_state(&certificate_key)
            .await
            .map_err(|error| anyhow!("failed to query sealed recovery witness state: {error}"))?
        {
            Some(existing_certificate_bytes) => {
                let existing: ioi_types::app::RecoveryWitnessCertificate =
                    codec::from_bytes_canonical(&existing_certificate_bytes).map_err(|e| {
                        anyhow!("failed to decode sealed recovery witness certificate: {e}")
                    })?;
                if existing != certificate {
                    tracing::warn!(
                        target: "consensus",
                        height = certificate.height,
                        witness_manifest_hash = %hex::encode(witness_manifest_hash),
                        "Skipping sealed recovery publication for this witness because a conflicting recovery witness certificate is already present in state."
                    );
                    continue;
                } else {
                    false
                }
            }
            None => true,
        };
        if publish_certificate {
            publisher
                .enqueue_call(
                    "publish_aft_recovery_witness_certificate@v1",
                    codec::to_bytes_canonical(&certificate).map_err(|e| anyhow!(e))?,
                )
                .await?;
        }

        let receipt = build_recovery_share_receipt_for_header(&block.header, &certificate)?;
        if publisher
            .workload_client
            .query_raw_state(&aft_missing_recovery_share_key(
                receipt.height,
                &receipt.witness_manifest_hash,
            ))
            .await
            .map_err(|error| {
                anyhow!("failed to query sealed missing recovery share state: {error}")
            })?
            .is_some()
        {
            tracing::warn!(
                target: "consensus",
                height = receipt.height,
                witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
                "Skipping sealed recovery share receipt publication because the witness already has an objective missing-share record."
            );
            continue;
        }
        match publisher
            .workload_client
            .query_raw_state(&aft_recovery_share_receipt_key(
                receipt.height,
                &receipt.witness_manifest_hash,
                &receipt.block_commitment_hash,
            ))
            .await
            .map_err(|error| {
                anyhow!("failed to query sealed recovery share receipt state: {error}")
            })? {
            Some(existing_receipt_bytes) => {
                let existing: RecoveryShareReceipt =
                    codec::from_bytes_canonical(&existing_receipt_bytes).map_err(|e| {
                        anyhow!("failed to decode sealed recovery share receipt: {e}")
                    })?;
                if existing != receipt {
                    tracing::warn!(
                        target: "consensus",
                        height = receipt.height,
                        witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
                        block_commitment_hash = %hex::encode(receipt.block_commitment_hash),
                        "Skipping sealed recovery share receipt publication because a conflicting receipt is already present in state."
                    );
                }
                continue;
            }
            None => {}
        }

        publisher
            .enqueue_call(
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt).map_err(|e| anyhow!(e))?,
            )
            .await?;
    }

    Ok(())
}

pub(super) fn select_supporting_recovery_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<RecoveryShareMaterial>> {
    if materials.is_empty() {
        return Err(anyhow!(
            "recovered publication bundle selection requires at least one recovery share material"
        ));
    }

    let mut ordered = materials.to_vec();
    ordered.sort_unstable_by(|left, right| {
        left.witness_manifest_hash.cmp(&right.witness_manifest_hash)
    });

    let mut unique: Vec<RecoveryShareMaterial> = Vec::new();
    for material in ordered {
        if let Some(previous) = unique.last() {
            if previous.witness_manifest_hash == material.witness_manifest_hash {
                if *previous != material {
                    return Err(anyhow!(
                        "recovered publication bundle selection encountered conflicting share materials for one witness"
                    ));
                }
                continue;
            }
        }
        unique.push(material);
    }

    let reference = unique
        .first()
        .ok_or_else(|| anyhow!("recovered publication bundle selection has no materials"))?;
    for material in &unique {
        if material.height != reference.height
            || material.block_commitment_hash != reference.block_commitment_hash
            || material.coding != reference.coding
        {
            return Err(anyhow!(
                "recovered publication bundle selection requires a uniform slot, block commitment, materialization kind, and threshold"
            ));
        }
    }

    let threshold = usize::from(reference.coding.recovery_threshold);
    if unique.len() < threshold {
        return Err(anyhow!(
            "recovered publication bundle selection requires threshold-many distinct share materials"
        ));
    }

    Ok(unique.into_iter().take(threshold).collect())
}

pub(super) fn build_recovered_publication_bundle(
    materials: &[RecoveryShareMaterial],
) -> Result<RecoveredPublicationBundle> {
    let supporting_materials = select_supporting_recovery_share_materials(materials)?;
    let supporting_witness_manifest_hashes =
        normalize_recovered_publication_bundle_supporting_witnesses(
            &supporting_materials
                .iter()
                .map(|material| material.witness_manifest_hash)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| anyhow!(error))?;
    let (payload, publication_bundle, bulletin_close) =
        recover_canonical_order_artifact_surface_from_share_materials(&supporting_materials)
            .map_err(|error| anyhow!(error))?;
    let (payload_v5, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&supporting_materials)
            .map_err(|error| anyhow!(error))?;
    Ok(RecoveredPublicationBundle {
        height: payload.height,
        block_commitment_hash: payload.block_commitment_hash,
        parent_block_commitment_hash: payload_v5.parent_block_hash,
        coding: supporting_materials[0].coding,
        supporting_witness_manifest_hashes,
        recoverable_slot_payload_hash: canonical_recoverable_slot_payload_v4_hash(&payload)
            .map_err(|error| anyhow!(error))?,
        recoverable_full_surface_hash: canonical_recoverable_slot_payload_v5_hash(&payload_v5)
            .map_err(|error| anyhow!(error))?,
        canonical_order_publication_bundle_hash: canonical_order_publication_bundle_hash(
            &publication_bundle,
        )
        .map_err(|error| anyhow!(error))?,
        canonical_bulletin_close_hash: canonical_bulletin_close_hash(&bulletin_close)
            .map_err(|error| anyhow!(error))?,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) async fn publish_experimental_locally_held_recovery_share_materials<S>(
    publisher: &GuardianRegistryPublisher,
    signer: &S,
    block: &Block<ChainTransaction>,
    witness_seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    reassignment_depth: u8,
    expected_bindings: &[ioi_types::app::GuardianWitnessRecoveryBindingAssignment],
) -> Result<Vec<RecoveryShareMaterial>>
where
    S: GuardianSigner + ?Sized,
{
    let mut available_materials = Vec::new();
    for expected_binding in expected_bindings {
        let Some(material) = signer
            .load_assigned_recovery_share_material(
                block.header.height,
                expected_binding.witness_manifest_hash,
                expected_binding.recovery_binding.clone(),
            )
            .await?
        else {
            continue;
        };

        let receipt = match verify_experimental_multi_witness_recovery_share_material(
            &block.header,
            &block.transactions,
            witness_seed,
            witness_set,
            reassignment_depth,
            &material,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                tracing::warn!(
                    target: "consensus",
                    height = block.header.height,
                    witness_manifest_hash = %hex::encode(expected_binding.witness_manifest_hash),
                    error = %error,
                    "Skipping recovery share-material publication because the stored reveal does not match the deterministic committed-surface plan."
                );
                continue;
            }
        };
        if receipt.share_commitment_hash != expected_binding.recovery_binding.share_commitment_hash
        {
            tracing::warn!(
                target: "consensus",
                height = block.header.height,
                witness_manifest_hash = %hex::encode(expected_binding.witness_manifest_hash),
                "Skipping recovery share-material publication because the stored reveal does not match the signed recovery binding."
            );
            continue;
        }
        if publisher
            .workload_client
            .query_raw_state(&aft_missing_recovery_share_key(
                material.height,
                &material.witness_manifest_hash,
            ))
            .await
            .map_err(|error| anyhow!("failed to query missing recovery share state: {error}"))?
            .is_some()
        {
            tracing::warn!(
                target: "consensus",
                height = material.height,
                witness_manifest_hash = %hex::encode(material.witness_manifest_hash),
                "Skipping recovery share-material publication because the witness already has an objective missing-share record."
            );
            continue;
        }

        if let Some(existing_receipt_bytes) = publisher
            .workload_client
            .query_raw_state(&aft_recovery_share_receipt_key(
                receipt.height,
                &receipt.witness_manifest_hash,
                &receipt.block_commitment_hash,
            ))
            .await
            .map_err(|error| anyhow!("failed to query recovery share receipt state: {error}"))?
        {
            let existing: RecoveryShareReceipt =
                codec::from_bytes_canonical(&existing_receipt_bytes)
                    .map_err(|e| anyhow!("failed to decode recovery share receipt: {e}"))?;
            if existing != receipt {
                tracing::warn!(
                    target: "consensus",
                    height = receipt.height,
                    witness_manifest_hash = %hex::encode(receipt.witness_manifest_hash),
                    block_commitment_hash = %hex::encode(receipt.block_commitment_hash),
                    "Skipping recovery share-material publication because the compact receipt lane carries conflicting evidence."
                );
                continue;
            }
        }

        let material_key = aft_recovery_share_material_key(
            material.height,
            &material.witness_manifest_hash,
            &material.block_commitment_hash,
        );
        match publisher
            .workload_client
            .query_raw_state(&material_key)
            .await
            .map_err(|error| anyhow!("failed to query recovery share material state: {error}"))?
        {
            Some(existing_material_bytes) => {
                let existing: RecoveryShareMaterial =
                    codec::from_bytes_canonical(&existing_material_bytes)
                        .map_err(|e| anyhow!("failed to decode recovery share material: {e}"))?;
                if existing != material {
                    tracing::warn!(
                        target: "consensus",
                        height = material.height,
                        witness_manifest_hash = %hex::encode(material.witness_manifest_hash),
                        block_commitment_hash = %hex::encode(material.block_commitment_hash),
                        "Skipping recovery share-material publication because a conflicting reveal is already present in state."
                    );
                    continue;
                }
                available_materials.push(material);
                continue;
            }
            None => {}
        }

        publisher
            .enqueue_call(
                "publish_aft_recovery_share_material@v1",
                codec::to_bytes_canonical(&material).map_err(|e| anyhow!(e))?,
            )
            .await?;
        available_materials.push(material);
    }

    Ok(available_materials)
}

pub(super) async fn publish_experimental_recovered_publication_bundle(
    publisher: &GuardianRegistryPublisher,
    materials: &[RecoveryShareMaterial],
) -> Result<Option<RecoveredPublicationBundle>> {
    let recovered = match build_recovered_publication_bundle(materials) {
        Ok(recovered) => recovered,
        Err(error) => {
            tracing::warn!(
                target: "consensus",
                error = %error,
                "Skipping recovered publication-bundle publication because the available public reveal set is not yet threshold-sufficient."
            );
            return Ok(None);
        }
    };

    let recovered_key = aft_recovered_publication_bundle_key(
        recovered.height,
        &recovered.block_commitment_hash,
        &recovered.supporting_witness_manifest_hashes,
    )
    .map_err(|error| anyhow!(error))?;
    match publisher
        .workload_client
        .query_raw_state(&recovered_key)
        .await
        .map_err(|error| anyhow!("failed to query recovered publication bundle state: {error}"))?
    {
        Some(existing_recovered_bytes) => {
            let existing: RecoveredPublicationBundle =
                codec::from_bytes_canonical(&existing_recovered_bytes)
                    .map_err(|e| anyhow!("failed to decode recovered publication bundle: {e}"))?;
            if existing != recovered {
                tracing::warn!(
                    target: "consensus",
                    height = recovered.height,
                    block_commitment_hash = %hex::encode(recovered.block_commitment_hash),
                    "Skipping recovered publication-bundle publication because a conflicting recovered object is already present in state."
                );
                return Ok(None);
            }
            Ok(Some(recovered))
        }
        None => {
            publisher
                .enqueue_call(
                    "publish_aft_recovered_publication_bundle@v1",
                    codec::to_bytes_canonical(&recovered).map_err(|e| anyhow!(e))?,
                )
                .await?;
            Ok(Some(recovered))
        }
    }
}
