use super::*;
use async_trait::async_trait;
use ioi_api::app::ChainStatus;
use ioi_api::chain::QueryStateResponse;
use ioi_types::app::{
    build_archived_recovered_history_profile_activation, write_validator_sets,
    ArchivedRecoveredHistoryProfileActivation, ChainId, GuardianQuorumCertificate,
    GuardianWitnessCertificate, QuorumCertificate, RecoveredCanonicalHeaderEntry,
    RecoveredCertifiedHeaderEntry, RecoveredRestartBlockHeaderEntry, RecoveryCodingDescriptor,
    RecoveryCodingFamily, StateAnchor, StateRoot, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
};
use ioi_types::error::ChainError;
use std::any::Any;

#[derive(Debug, Default)]
struct TestWorkloadClient;

#[async_trait]
impl WorkloadClientApi for TestWorkloadClient {
    async fn process_block(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_blocks_range(
        &self,
        _since: u64,
        _max_blocks: u32,
        _max_bytes: u32,
    ) -> std::result::Result<Vec<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_block_by_height(
        &self,
        _height: u64,
    ) -> std::result::Result<Option<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn check_transactions_at(
        &self,
        _anchor: StateAnchor,
        _expected_timestamp_secs: u64,
        _txs: Vec<ChainTransaction>,
    ) -> std::result::Result<Vec<std::result::Result<(), String>>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn query_state_at(
        &self,
        _root: StateRoot,
        _key: &[u8],
    ) -> std::result::Result<QueryStateResponse, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn query_raw_state(
        &self,
        _key: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, ChainError> {
        Ok(None)
    }

    async fn prefix_scan(
        &self,
        _prefix: &[u8],
    ) -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_staked_validators(
        &self,
    ) -> std::result::Result<BTreeMap<AccountId, u64>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_genesis_status(&self) -> std::result::Result<bool, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn update_block_header(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(), ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug, Default)]
struct StaticStateWorkloadClient {
    raw_state: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[async_trait]
impl WorkloadClientApi for StaticStateWorkloadClient {
    async fn process_block(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_blocks_range(
        &self,
        _since: u64,
        _max_blocks: u32,
        _max_bytes: u32,
    ) -> std::result::Result<Vec<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_block_by_height(
        &self,
        _height: u64,
    ) -> std::result::Result<Option<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn check_transactions_at(
        &self,
        _anchor: StateAnchor,
        _expected_timestamp_secs: u64,
        _txs: Vec<ChainTransaction>,
    ) -> std::result::Result<Vec<std::result::Result<(), String>>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn query_state_at(
        &self,
        _root: StateRoot,
        _key: &[u8],
    ) -> std::result::Result<QueryStateResponse, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn query_raw_state(
        &self,
        key: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, ChainError> {
        Ok(self.raw_state.get(key).cloned())
    }

    async fn prefix_scan(
        &self,
        prefix: &[u8],
    ) -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        Ok(self
            .raw_state
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    async fn get_staked_validators(
        &self,
    ) -> std::result::Result<BTreeMap<AccountId, u64>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_genesis_status(&self) -> std::result::Result<bool, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn update_block_header(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(), ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused in finalize unit tests".to_string(),
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug, Default)]
struct MockRecoveryRevealSigner {
    materials: BTreeMap<([u8; 32], [u8; 32]), RecoveryShareMaterial>,
}

#[async_trait]
impl GuardianSigner for MockRecoveryRevealSigner {
    async fn sign_consensus_payload(
        &self,
        _payload_hash: [u8; 32],
        _height: u64,
        _view: u64,
        _experimental_witness_manifest: Option<([u8; 32], u8)>,
        _experimental_recovery_binding: Option<GuardianWitnessRecoveryBinding>,
    ) -> Result<SignatureBundle> {
        Err(anyhow!("unused in recovery reveal tests"))
    }

    async fn load_assigned_recovery_share_material(
        &self,
        _height: u64,
        witness_manifest_hash: [u8; 32],
        recovery_binding: GuardianWitnessRecoveryBinding,
    ) -> Result<Option<RecoveryShareMaterial>> {
        Ok(self
            .materials
            .get(&(
                witness_manifest_hash,
                recovery_binding.share_commitment_hash,
            ))
            .cloned())
    }

    fn public_key(&self) -> Vec<u8> {
        Vec::new()
    }
}

fn sample_block_header() -> ioi_types::app::BlockHeader {
    ioi_types::app::BlockHeader {
        height: 11,
        view: 4,
        parent_hash: [1u8; 32],
        parent_state_root: StateRoot(vec![2u8; 32]),
        state_root: StateRoot(vec![3u8; 32]),
        transactions_root: vec![4u8; 32],
        timestamp: 1_700_000_000,
        timestamp_ms: 1_700_000_000_000,
        gas_used: 0,
        validator_set: vec![vec![5u8; 32]],
        producer_account_id: AccountId([6u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [7u8; 32],
        producer_pubkey: vec![8u8; 32],
        oracle_counter: 9,
        oracle_trace_hash: [10u8; 32],
        guardian_certificate: Some(GuardianQuorumCertificate {
            manifest_hash: [11u8; 32],
            epoch: 9,
            decision_hash: [12u8; 32],
            counter: 13,
            trace_hash: [14u8; 32],
            measurement_root: [15u8; 32],
            signers_bitfield: vec![1],
            aggregated_signature: vec![2],
            log_checkpoint: Some(GuardianLogCheckpoint {
                log_id: "guardian-log".to_string(),
                tree_size: 7,
                root_hash: [16u8; 32],
                timestamp_ms: 1_700_000_000_000,
                signature: vec![3],
                proof: None,
            }),
            experimental_witness_certificate: None,
        }),
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
        parent_qc: QuorumCertificate {
            height: 10,
            view: 3,
            block_hash: [17u8; 32],
            signatures: Vec::new(),
            aggregated_signature: vec![4],
            signers_bitfield: vec![1],
        },
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        signature: vec![5],
    }
}

fn sample_block_with_recovery_scaffold() -> (
    Block<ChainTransaction>,
    ExperimentalRecoveryScaffoldArtifacts,
) {
    let mut header = sample_block_header();
    let transactions = Vec::new();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let scaffold =
        build_experimental_recovery_scaffold_artifacts(&header, &transactions, [0x41u8; 32], 0)
            .expect("recovery scaffold");
    header
        .guardian_certificate
        .as_mut()
        .expect("sample header must carry guardian certificate")
        .experimental_witness_certificate = Some(GuardianWitnessCertificate {
        manifest_hash: [0x41u8; 32],
        stratum_id: "stratum-a".into(),
        epoch: 9,
        statement_hash: [0x42u8; 32],
        signers_bitfield: vec![0b0000_0011],
        aggregated_signature: vec![0x43],
        reassignment_depth: 0,
        recovery_binding: Some(scaffold.recovery_binding().expect("recovery binding")),
        log_checkpoint: None,
    });
    (
        Block {
            header,
            transactions,
        },
        scaffold,
    )
}

fn sample_block_with_sealed_recovery_bindings() -> (
    Block<ChainTransaction>,
    RecoveryCapsule,
    Vec<ioi_types::app::GuardianWitnessRecoveryBindingAssignment>,
) {
    let (mut header, transactions) = sample_block_header_with_ordered_transactions(0x5a);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x91u8; 32], [0x92u8; 32], [0x93u8; 32], [0x94u8; 32]]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_parity_family_share_count(),
    )
    .expect("derive parity-family witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_parity_family_recovery_threshold(),
    )
    .expect("build parity-family multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build parity-family multi-witness recovery bindings");
    let guardian_certificate = header
        .guardian_certificate
        .as_ref()
        .expect("guardian certificate")
        .clone();
    header.sealed_finality_proof = Some(SealedFinalityProof {
        epoch: witness_seed.epoch,
        finality_tier: ioi_types::app::FinalityTier::SealedFinal,
        collapse_state: ioi_types::app::CollapseState::SealedFinal,
        guardian_manifest_hash: guardian_certificate.manifest_hash,
        guardian_decision_hash: guardian_certificate.decision_hash,
        guardian_counter: guardian_certificate.counter,
        guardian_trace_hash: guardian_certificate.trace_hash,
        guardian_measurement_root: guardian_certificate.measurement_root,
        policy_hash: [0x94u8; 32],
        witness_certificates: binding_assignments
            .iter()
            .enumerate()
            .map(|(index, assignment)| GuardianWitnessCertificate {
                manifest_hash: assignment.witness_manifest_hash,
                stratum_id: format!("stratum-{index}"),
                epoch: witness_seed.epoch,
                statement_hash: [0x95u8.wrapping_add(index as u8); 32],
                signers_bitfield: vec![0b0000_0011],
                aggregated_signature: vec![0x97u8.wrapping_add(index as u8)],
                reassignment_depth: 0,
                recovery_binding: Some(assignment.recovery_binding.clone()),
                log_checkpoint: None,
            })
            .collect(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: Vec::new(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: None,
        observer_challenge_commitment: None,
        observer_canonical_close: None,
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    });
    (
        Block {
            header,
            transactions,
        },
        capsule,
        binding_assignments,
    )
}

fn sample_recovery_transactions(seed: u8) -> Vec<ChainTransaction> {
    vec![
        ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([seed.wrapping_add(0x10); 32]),
                nonce: 1,
                chain_id: ioi_types::app::ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![seed, seed.wrapping_add(1)],
            },
            signature_proof: SignatureProof::default(),
        })),
        ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([seed.wrapping_add(0x11); 32]),
                nonce: 2,
                chain_id: ioi_types::app::ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![seed.wrapping_add(2), seed.wrapping_add(3)],
            },
            signature_proof: SignatureProof::default(),
        })),
    ]
}

fn sample_block_header_with_ordered_transactions_from_header(
    mut header: ioi_types::app::BlockHeader,
    seed: u8,
) -> (ioi_types::app::BlockHeader, Vec<ChainTransaction>) {
    let transactions = ioi_types::app::canonicalize_transactions_for_header(
        &header,
        &sample_recovery_transactions(seed),
    )
    .expect("canonicalized transactions");
    let transaction_hashes = transactions
        .iter()
        .map(|transaction| transaction.hash().expect("transaction hash"))
        .collect::<Vec<_>>();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&transaction_hashes)
            .expect("transactions root");
    (header, transactions)
}

fn sample_block_header_with_ordered_transactions(
    seed: u8,
) -> (ioi_types::app::BlockHeader, Vec<ChainTransaction>) {
    sample_block_header_with_ordered_transactions_from_header(sample_block_header(), seed)
}

fn recovered_publication_frontier_header(
    payload: &RecoverableSlotPayloadV5,
) -> ioi_types::app::BlockHeader {
    let mut header = sample_block_header();
    header.height = payload.height;
    header.view = payload.view;
    header.parent_hash = payload.parent_block_hash;
    header.parent_state_root = StateRoot(
        payload
            .canonical_order_certificate
            .resulting_state_root_hash
            .to_vec(),
    );
    header.state_root = StateRoot(
        payload
            .canonical_order_certificate
            .resulting_state_root_hash
            .to_vec(),
    );
    header.transactions_root = payload
        .canonical_order_certificate
        .ordered_transactions_root_hash
        .to_vec();
    header.timestamp_ms = payload
        .canonical_order_certificate
        .bulletin_commitment
        .cutoff_timestamp_ms;
    header.timestamp = header.timestamp_ms / 1_000;
    header.producer_account_id = payload.producer_account_id;
    header.canonical_order_certificate = Some(payload.canonical_order_certificate.clone());
    header.publication_frontier = None;
    header
}

fn sample_guardian_witness_seed() -> GuardianWitnessEpochSeed {
    GuardianWitnessEpochSeed {
        epoch: 9,
        seed: [0x21u8; 32],
        checkpoint_interval_blocks: 16,
        max_reassignment_depth: 0,
    }
}

fn sample_guardian_witness_set(manifest_hashes: Vec<[u8; 32]>) -> GuardianWitnessSet {
    GuardianWitnessSet {
        epoch: 9,
        manifest_hashes,
        checkpoint_interval_blocks: 16,
    }
}

fn synthetic_recovered_publication_bundle_for_height(
    template: &RecoveredPublicationBundle,
    height: u64,
) -> RecoveredPublicationBundle {
    let seed = (height as u8).wrapping_mul(7).wrapping_add(0x31);
    let mut bundle = template.clone();
    bundle.height = height;
    bundle.block_commitment_hash = [seed; 32];
    bundle.parent_block_commitment_hash = [seed.wrapping_sub(1); 32];
    bundle.recoverable_slot_payload_hash = [seed.wrapping_add(1); 32];
    bundle.recoverable_full_surface_hash = [seed.wrapping_add(2); 32];
    bundle.canonical_order_publication_bundle_hash = [seed.wrapping_add(3); 32];
    bundle.canonical_bulletin_close_hash = [seed.wrapping_add(4); 32];
    bundle
}

fn validator_sets(validators: &[(u8, u128)]) -> ValidatorSetsV1 {
    let entries = validators
        .iter()
        .map(|(account, weight)| ValidatorV1 {
            account_id: AccountId([*account; 32]),
            weight: *weight,
            consensus_key: Default::default(),
        })
        .collect::<Vec<_>>();
    ValidatorSetsV1 {
        current: ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: entries.iter().map(|validator| validator.weight).sum(),
            validators: entries,
        },
        next: None,
    }
}

fn sample_previous_canonical_collapse_object(height: u64, seed: u8) -> CanonicalCollapseObject {
    CanonicalCollapseObject {
        height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: ioi_types::app::CanonicalOrderingCollapse {
            height,
            kind: ioi_types::app::CanonicalCollapseKind::Close,
            bulletin_commitment_hash: [seed; 32],
            bulletin_availability_certificate_hash: [seed.wrapping_add(1); 32],
            bulletin_retrievability_profile_hash: [0u8; 32],
            bulletin_shard_manifest_hash: [0u8; 32],
            bulletin_custody_receipt_hash: [0u8; 32],
            bulletin_close_hash: [seed.wrapping_add(2); 32],
            canonical_order_certificate_hash: [seed.wrapping_add(3); 32],
        },
        sealing: None,
        transactions_root_hash: [seed.wrapping_add(4); 32],
        resulting_state_root_hash: [seed.wrapping_add(5); 32],
    }
}

fn synthetic_archived_restart_page(
    segment: &ArchivedRecoveredHistorySegment,
    terminal_block_hash: [u8; 32],
) -> ArchivedRecoveredRestartPage {
    let mut entries = Vec::new();
    let mut previous_block_hash = [0x31u8; 32];
    let mut previous_state_root_hash = [0x41u8; 32];
    for height in segment.start_height..=segment.end_height {
        let seed = (height as u8).wrapping_mul(5).wrapping_add(0x53);
        let block_hash = if height == segment.end_height {
            terminal_block_hash
        } else {
            [seed; 32]
        };
        let certified_header = RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height,
                view: height + 10,
                canonical_block_commitment_hash: block_hash,
                parent_block_commitment_hash: previous_block_hash,
                transactions_root_hash: [seed.wrapping_add(1); 32],
                resulting_state_root_hash: [seed.wrapping_add(2); 32],
                previous_canonical_collapse_commitment_hash: [seed.wrapping_add(3); 32],
            },
            certified_parent_quorum_certificate: QuorumCertificate {
                height: height.saturating_sub(1),
                view: height + 9,
                block_hash: previous_block_hash,
                ..Default::default()
            },
            certified_parent_resulting_state_root_hash: previous_state_root_hash,
        };
        entries.push(RecoveredRestartBlockHeaderEntry {
            certified_header: certified_header.clone(),
            header: BlockHeader {
                height,
                view: certified_header.header.view,
                parent_hash: previous_block_hash,
                parent_state_root: StateRoot(previous_state_root_hash.to_vec()),
                state_root: StateRoot(certified_header.header.resulting_state_root_hash.to_vec()),
                transactions_root: certified_header.header.transactions_root_hash.to_vec(),
                timestamp: 1_760_000_000 + height,
                timestamp_ms: (1_760_000_000 + height) * 1_000,
                gas_used: 0,
                validator_set: Vec::new(),
                producer_account_id: AccountId([seed.wrapping_add(4); 32]),
                producer_key_suite: SignatureSuite::ED25519,
                producer_pubkey_hash: [seed.wrapping_add(5); 32],
                producer_pubkey: Vec::new(),
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
                parent_qc: certified_header.certified_parent_quorum_certificate.clone(),
                previous_canonical_collapse_commitment_hash: certified_header
                    .header
                    .previous_canonical_collapse_commitment_hash,
                canonical_collapse_extension_certificate: None,
                publication_frontier: None,
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate: None,
                signature: Vec::new(),
            },
        });
        previous_block_hash = block_hash;
        previous_state_root_hash = certified_header.header.resulting_state_root_hash;
    }
    build_archived_recovered_restart_page(segment, &entries)
        .expect("synthetic archived recovered restart page")
}

fn sample_parity_family_share_count() -> u16 {
    4
}

fn sample_parity_family_recovery_threshold() -> u16 {
    sample_parity_family_share_count() - 1
}

fn sample_gf256_2_of_4_share_count() -> u16 {
    4
}

fn sample_gf256_2_of_4_recovery_threshold() -> u16 {
    2
}

fn sample_gf256_3_of_5_share_count() -> u16 {
    5
}

fn sample_gf256_3_of_5_recovery_threshold() -> u16 {
    3
}

fn sample_gf256_3_of_7_share_count() -> u16 {
    7
}

fn sample_gf256_3_of_7_recovery_threshold() -> u16 {
    3
}

fn sample_gf256_4_of_6_share_count() -> u16 {
    6
}

fn sample_gf256_4_of_6_recovery_threshold() -> u16 {
    4
}

fn sample_gf256_4_of_7_share_count() -> u16 {
    7
}

fn sample_gf256_4_of_7_recovery_threshold() -> u16 {
    4
}

fn xor_recovery_coding(share_count: u16, recovery_threshold: u16) -> RecoveryCodingDescriptor {
    RecoveryCodingDescriptor {
        family: RecoveryCodingFamily::SystematicXorKOfKPlus1V1,
        share_count,
        recovery_threshold,
    }
}

fn gf256_recovery_coding(share_count: u16, recovery_threshold: u16) -> RecoveryCodingDescriptor {
    RecoveryCodingDescriptor {
        family: RecoveryCodingFamily::SystematicGf256KOfNV1,
        share_count,
        recovery_threshold,
    }
}

fn sample_manifest_hashes(seed: u8, share_count: u16) -> Vec<[u8; 32]> {
    (0..share_count)
        .map(|offset| [seed.wrapping_add(offset as u8); 32])
        .collect()
}

fn collect_index_combinations(total: usize, choose: usize) -> Vec<Vec<usize>> {
    fn recurse(
        total: usize,
        choose: usize,
        next_index: usize,
        current: &mut Vec<usize>,
        all: &mut Vec<Vec<usize>>,
    ) {
        if current.len() == choose {
            all.push(current.clone());
            return;
        }
        let remaining = choose - current.len();
        for index in next_index..=total - remaining {
            current.push(index);
            recurse(total, choose, index + 1, current, all);
            current.pop();
        }
    }

    if choose == 0 {
        return vec![Vec::new()];
    }
    let mut all = Vec::new();
    let mut current = Vec::new();
    recurse(total, choose, 0, &mut current, &mut all);
    all
}

fn select_recovery_share_materials(
    materials: &[RecoveryShareMaterial],
    indices: &[usize],
) -> Vec<RecoveryShareMaterial> {
    indices
        .iter()
        .map(|index| materials[*index].clone())
        .collect()
}

fn assert_coded_recovery_family_subset_conformance_case(
    transaction_seed: u8,
    manifest_seed: u8,
    share_count: u16,
    recovery_threshold: u16,
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(transaction_seed);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(sample_manifest_hashes(manifest_seed, share_count));
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        share_count,
        recovery_threshold,
    )
    .expect("share materials");
    let expected_coding = experimental_multi_witness_coding(share_count, recovery_threshold);
    assert_eq!(materials[0].coding, expected_coding);
    assert!(expected_coding
        .family_contract()
        .expect("coded recovery-family contract")
        .supports_coded_payload_reconstruction());
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&expected_payload.canonical_order_publication_bundle_bytes)
            .expect("expected publication bundle");

    for material in &materials {
        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify in conformance harness");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }

    for indices in collect_index_combinations(materials.len(), usize::from(recovery_threshold)) {
        let subset = select_recovery_share_materials(&materials, &indices);
        let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&subset)
            .unwrap_or_else(|error| {
                panic!(
                    "threshold subset {indices:?} should reconstruct for {}-of-{}: {error}",
                    recovery_threshold, share_count
                )
            });
        let (recovered_payload, recovered_bundle) =
                recover_canonical_order_publication_bundle_from_share_materials(&subset)
                    .unwrap_or_else(|error| {
                        panic!(
                            "threshold subset {indices:?} should recover publication bundle for {}-of-{}: {error}",
                            recovery_threshold, share_count
                        )
                    });
        assert_eq!(recovered, expected_payload);
        assert_eq!(recovered_payload, expected_payload);
        assert_eq!(recovered_bundle, expected_bundle);
    }

    for indices in collect_index_combinations(
        materials.len(),
        usize::from(recovery_threshold.saturating_sub(1)),
    ) {
        let subset = select_recovery_share_materials(&materials, &indices);
        let error = recover_recoverable_slot_payload_v3_from_share_materials(&subset)
            .expect_err("below-threshold subset should not reconstruct");
        let error_text = error.to_string();
        assert!(
            error_text.contains(&format!(
                "requires at least {recovery_threshold} distinct share reveals"
            )),
            "unexpected below-threshold error for {}-of-{} subset {indices:?}: {error_text}",
            recovery_threshold,
            share_count
        );
    }
}

fn assert_coded_recovery_family_commitment_determinism_case(
    transaction_seed: u8,
    manifest_seed: u8,
    alternate_manifest_seed: u8,
    share_count: u16,
    recovery_threshold: u16,
) {
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(sample_manifest_hashes(manifest_seed, share_count));
    let alternate_witness_set =
        sample_guardian_witness_set(sample_manifest_hashes(alternate_manifest_seed, share_count));
    let (header_a, transactions_a) =
        sample_block_header_with_ordered_transactions(transaction_seed);
    let (header_b, transactions_b) =
        sample_block_header_with_ordered_transactions(transaction_seed.wrapping_add(1));
    let materials_a = build_experimental_multi_witness_recovery_share_materials(
        &header_a,
        &transactions_a,
        &witness_seed,
        &witness_set,
        0,
        share_count,
        recovery_threshold,
    )
    .expect("share materials a");
    let materials_a_repeat = build_experimental_multi_witness_recovery_share_materials(
        &header_a,
        &transactions_a,
        &witness_seed,
        &witness_set,
        0,
        share_count,
        recovery_threshold,
    )
    .expect("share materials a repeat");
    let materials_b = build_experimental_multi_witness_recovery_share_materials(
        &header_b,
        &transactions_b,
        &witness_seed,
        &witness_set,
        0,
        share_count,
        recovery_threshold,
    )
    .expect("share materials b");
    let materials_membership = build_experimental_multi_witness_recovery_share_materials(
        &header_a,
        &transactions_a,
        &witness_seed,
        &alternate_witness_set,
        0,
        share_count,
        recovery_threshold,
    )
    .expect("share materials membership");

    let commitments_a = materials_a
        .iter()
        .map(|material| material.share_commitment_hash)
        .collect::<Vec<_>>();
    let commitments_a_repeat = materials_a_repeat
        .iter()
        .map(|material| material.share_commitment_hash)
        .collect::<Vec<_>>();
    let commitments_b = materials_b
        .iter()
        .map(|material| material.share_commitment_hash)
        .collect::<Vec<_>>();
    let commitments_membership = materials_membership
        .iter()
        .map(|material| material.share_commitment_hash)
        .collect::<Vec<_>>();

    let bytes_a = materials_a
        .iter()
        .map(|material| material.material_bytes.clone())
        .collect::<Vec<_>>();
    let bytes_a_repeat = materials_a_repeat
        .iter()
        .map(|material| material.material_bytes.clone())
        .collect::<Vec<_>>();
    let bytes_b = materials_b
        .iter()
        .map(|material| material.material_bytes.clone())
        .collect::<Vec<_>>();
    let bytes_membership = materials_membership
        .iter()
        .map(|material| material.material_bytes.clone())
        .collect::<Vec<_>>();

    assert_eq!(commitments_a, commitments_a_repeat);
    assert_eq!(bytes_a, bytes_a_repeat);
    assert_ne!(commitments_a, commitments_b);
    assert_ne!(bytes_a, bytes_b);
    assert_ne!(commitments_a, commitments_membership);
    assert_eq!(bytes_a, bytes_membership);
}

#[test]
fn experimental_recovery_scaffold_changes_with_witness_manifest() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
        .expect("canonical order certificate");
    let scaffold_a = build_experimental_recovery_scaffold_artifacts(&header, &[], [0x41u8; 32], 0)
        .expect("scaffold a");
    let scaffold_b = build_experimental_recovery_scaffold_artifacts(&header, &[], [0x42u8; 32], 0)
        .expect("scaffold b");

    assert_eq!(
        scaffold_a.capsule.payload_commitment_hash,
        certificate
            .bulletin_availability_certificate
            .recoverability_root
    );
    assert_eq!(
        scaffold_b.capsule.payload_commitment_hash,
        certificate
            .bulletin_availability_certificate
            .recoverability_root
    );
    assert_ne!(scaffold_a.capsule, scaffold_b.capsule);
    assert_ne!(
        scaffold_a.capsule.coding_root_hash,
        scaffold_b.capsule.coding_root_hash
    );
    assert_ne!(
        scaffold_a.share_commitment_hash,
        scaffold_b.share_commitment_hash
    );
    assert_eq!(
        scaffold_a.capsule.coding.family,
        RecoveryCodingFamily::DeterministicScaffoldV1
    );
    assert_eq!(scaffold_a.capsule.coding.recovery_threshold, 1);
}

#[test]
fn experimental_multi_witness_recovery_plan_changes_with_membership() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let plan_a = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &witness_seed,
        &sample_guardian_witness_set(vec![[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]]),
        0,
        3,
        2,
    )
    .expect("plan a");
    let plan_b = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &witness_seed,
        &sample_guardian_witness_set(vec![[0x31u8; 32], [0x32u8; 32], [0x34u8; 32]]),
        0,
        3,
        2,
    )
    .expect("plan b");

    assert_eq!(
        plan_a.payload_commitment_hash,
        certificate
            .bulletin_availability_certificate
            .recoverability_root
    );
    assert_eq!(
        plan_a.payload_commitment_hash,
        plan_b.payload_commitment_hash
    );
    assert_ne!(
        plan_a.recovery_committee_root_hash,
        plan_b.recovery_committee_root_hash
    );
    assert_ne!(plan_a.coding_root_hash, plan_b.coding_root_hash);
    assert_ne!(
        plan_a
            .shares
            .iter()
            .map(|share| share.assignment.manifest_hash)
            .collect::<Vec<_>>(),
        plan_b
            .shares
            .iter()
            .map(|share| share.assignment.manifest_hash)
            .collect::<Vec<_>>()
    );
}

#[test]
fn experimental_multi_witness_recovery_plan_changes_with_threshold() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x41u8; 32], [0x42u8; 32], [0x43u8; 32], [0x44u8; 32]]);
    let threshold_two = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("threshold two plan");
    let threshold_three = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        sample_parity_family_share_count(),
        sample_parity_family_recovery_threshold(),
    )
    .expect("threshold three plan");

    assert_eq!(
        threshold_two.payload_commitment_hash,
        certificate
            .bulletin_availability_certificate
            .recoverability_root
    );
    assert_eq!(
        threshold_two.payload_commitment_hash,
        threshold_three.payload_commitment_hash
    );
    assert_eq!(threshold_two.share_count, threshold_three.share_count);
    assert_eq!(
        threshold_two.coding,
        gf256_recovery_coding(
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
    );
    assert_eq!(
        threshold_three.coding,
        xor_recovery_coding(
            sample_parity_family_share_count(),
            sample_parity_family_recovery_threshold(),
        )
    );
    assert_ne!(
        threshold_two.recovery_threshold,
        threshold_three.recovery_threshold
    );
    assert_ne!(
        threshold_two.coding_root_hash,
        threshold_three.coding_root_hash
    );
    assert_ne!(
        threshold_two
            .shares
            .iter()
            .map(|share| share.share_commitment_hash)
            .collect::<Vec<_>>(),
        threshold_three
            .shares
            .iter()
            .map(|share| share.share_commitment_hash)
            .collect::<Vec<_>>()
    );
}

#[test]
fn experimental_multi_witness_recovery_plan_rejects_threshold_one() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let error = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &sample_guardian_witness_seed(),
        &sample_guardian_witness_set(vec![[0x51u8; 32], [0x52u8; 32]]),
        0,
        2,
        1,
    )
    .expect_err("threshold-one plan should be rejected");

    assert!(
        error
            .to_string()
            .contains("requires threshold at least two"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn experimental_multi_witness_recovery_share_material_builds_and_verifies() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x51);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x61u8; 32], [0x62u8; 32], [0x63u8; 32], [0x64u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("share materials");

    assert_eq!(
        materials.len(),
        usize::from(sample_gf256_2_of_4_share_count())
    );
    let expected_block_commitment_hash =
        canonical_block_commitment_hash(&header).expect("block commitment hash");
    for (expected_index, material) in materials.iter().enumerate() {
        assert_eq!(material.height, header.height);
        assert_eq!(
            material.block_commitment_hash,
            expected_block_commitment_hash
        );
        assert_eq!(
            material.coding,
            gf256_recovery_coding(
                sample_gf256_2_of_4_share_count(),
                sample_gf256_2_of_4_recovery_threshold(),
            )
        );
        assert_eq!(usize::from(material.share_index), expected_index);
        assert!(!material.material_bytes.is_empty());

        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_three_of_five_gf256()
{
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5b);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0x91u8; 32],
        [0x92u8; 32],
        [0x93u8; 32],
        [0x94u8; 32],
        [0x95u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_5_share_count(),
        sample_gf256_3_of_5_recovery_threshold(),
    )
    .expect("share materials");

    assert_eq!(
        materials.len(),
        usize::from(sample_gf256_3_of_5_share_count())
    );
    let expected_block_commitment_hash =
        canonical_block_commitment_hash(&header).expect("block commitment hash");
    for (expected_index, material) in materials.iter().enumerate() {
        assert_eq!(material.height, header.height);
        assert_eq!(
            material.block_commitment_hash,
            expected_block_commitment_hash
        );
        assert_eq!(
            material.coding,
            gf256_recovery_coding(
                sample_gf256_3_of_5_share_count(),
                sample_gf256_3_of_5_recovery_threshold(),
            )
        );
        assert_eq!(usize::from(material.share_index), expected_index);
        assert!(!material.material_bytes.is_empty());

        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_four_of_six_gf256() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5e);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xc1u8; 32],
        [0xc2u8; 32],
        [0xc3u8; 32],
        [0xc4u8; 32],
        [0xc5u8; 32],
        [0xc6u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_4_of_6_share_count(),
        sample_gf256_4_of_6_recovery_threshold(),
    )
    .expect("share materials");

    assert_eq!(
        materials.len(),
        usize::from(sample_gf256_4_of_6_share_count())
    );
    let expected_block_commitment_hash =
        canonical_block_commitment_hash(&header).expect("block commitment hash");
    for (expected_index, material) in materials.iter().enumerate() {
        assert_eq!(material.height, header.height);
        assert_eq!(
            material.block_commitment_hash,
            expected_block_commitment_hash
        );
        assert_eq!(
            material.coding,
            gf256_recovery_coding(
                sample_gf256_4_of_6_share_count(),
                sample_gf256_4_of_6_recovery_threshold(),
            )
        );
        assert_eq!(usize::from(material.share_index), expected_index);
        assert!(!material.material_bytes.is_empty());

        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_four_of_seven_gf256()
{
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x61);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xf1u8; 32],
        [0xf2u8; 32],
        [0xf3u8; 32],
        [0xf4u8; 32],
        [0xf5u8; 32],
        [0xf6u8; 32],
        [0xf7u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_4_of_7_share_count(),
        sample_gf256_4_of_7_recovery_threshold(),
    )
    .expect("share materials");

    assert_eq!(
        materials.len(),
        usize::from(sample_gf256_4_of_7_share_count())
    );
    let expected_block_commitment_hash =
        canonical_block_commitment_hash(&header).expect("block commitment hash");
    for (expected_index, material) in materials.iter().enumerate() {
        assert_eq!(material.height, header.height);
        assert_eq!(
            material.block_commitment_hash,
            expected_block_commitment_hash
        );
        assert_eq!(
            material.coding,
            gf256_recovery_coding(
                sample_gf256_4_of_7_share_count(),
                sample_gf256_4_of_7_recovery_threshold(),
            )
        );
        assert_eq!(usize::from(material.share_index), expected_index);
        assert!(!material.material_bytes.is_empty());

        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_four_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x52);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x64u8; 32], [0x65u8; 32], [0x66u8; 32], [0x67u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_parity_family_share_count(),
        sample_parity_family_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[2].clone(),
        materials[3].clone(),
    ])
    .expect("payload should reconstruct from three of four parity-family shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_two_of_four_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5a);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x71u8; 32], [0x72u8; 32], [0x73u8; 32], [0x74u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[1].clone(),
        materials[3].clone(),
    ])
    .expect("payload should reconstruct from two of four gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_five_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5c);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xa1u8; 32],
        [0xa2u8; 32],
        [0xa3u8; 32],
        [0xa4u8; 32],
        [0xa5u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_5_share_count(),
        sample_gf256_3_of_5_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[3].clone(),
        materials[4].clone(),
    ])
    .expect("payload should reconstruct from three of five gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_seven_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5d);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xb1u8; 32],
        [0xb2u8; 32],
        [0xb3u8; 32],
        [0xb4u8; 32],
        [0xb5u8; 32],
        [0xb6u8; 32],
        [0xb7u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_7_share_count(),
        sample_gf256_3_of_7_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[3].clone(),
        materials[6].clone(),
    ])
    .expect("payload should reconstruct from three of seven gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_full_positive_close_surface_from_three_of_seven_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5e);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xc1u8; 32],
        [0xc2u8; 32],
        [0xc3u8; 32],
        [0xc4u8; 32],
        [0xc5u8; 32],
        [0xc6u8; 32],
        [0xc7u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_7_share_count(),
        sample_gf256_3_of_7_recovery_threshold(),
    )
    .expect("share materials");

    let support_materials = [
        materials[0].clone(),
        materials[3].clone(),
        materials[6].clone(),
    ];
    let (recovered_payload, recovered_bundle, recovered_close) =
        recover_canonical_order_artifact_surface_from_share_materials(&support_materials).expect(
            "full positive close surface should reconstruct from three of seven gf256 shards",
        );
    let (recovered_full_surface, _, _, recovered_surface_entries) =
        recover_full_canonical_order_surface_from_share_materials(&support_materials).expect(
            "full extractable bulletin surface should reconstruct from three of seven gf256 shards",
        );
    let expected_payload = build_recoverable_slot_payload_v4(&header, &transactions, &certificate)
        .expect("recoverable payload v4");
    let expected_full_surface =
        build_recoverable_slot_payload_v5(&header, &transactions, &certificate)
            .expect("recoverable payload v5");
    let expected_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&expected_payload.canonical_order_publication_bundle_bytes)
            .expect("decode expected publication bundle");
    let expected_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&expected_bundle)
            .expect("verify expected publication bundle");
    let expected_surface = expected_bundle.bulletin_entries.clone();
    let recovered_object = build_recovered_publication_bundle(&support_materials)
        .expect("recovered publication bundle object");

    assert_eq!(recovered_payload, expected_payload);
    assert_eq!(recovered_full_surface, expected_full_surface);
    assert_eq!(recovered_bundle, expected_bundle);
    assert_eq!(recovered_close, expected_close);
    assert_eq!(recovered_surface_entries, expected_surface);
    assert_eq!(
        recovered_object.recoverable_slot_payload_hash,
        canonical_recoverable_slot_payload_v4_hash(&expected_payload)
            .expect("recoverable payload v4 hash")
    );
    assert_eq!(
        recovered_object.recoverable_full_surface_hash,
        canonical_recoverable_slot_payload_v5_hash(&expected_full_surface)
            .expect("recoverable payload v5 hash")
    );
    assert_eq!(
        recovered_object.canonical_bulletin_close_hash,
        canonical_bulletin_close_hash(&expected_close).expect("canonical bulletin close hash")
    );
}

#[test]
fn experimental_multi_witness_recovery_recovered_surfaces_chain_publication_frontiers_across_two_slots(
) {
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xe1u8; 32],
        [0xe2u8; 32],
        [0xe3u8; 32],
        [0xe4u8; 32],
        [0xe5u8; 32],
        [0xe6u8; 32],
        [0xe7u8; 32],
    ]);

    let mut base_header_a = sample_block_header();
    base_header_a.height = 1;
    base_header_a.timestamp += 1;
    base_header_a.timestamp_ms += 1_000;
    let (header_a, transactions_a) =
        sample_block_header_with_ordered_transactions_from_header(base_header_a, 0x64);
    let materials_a = build_experimental_multi_witness_recovery_share_materials(
        &header_a,
        &transactions_a,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_7_share_count(),
        sample_gf256_3_of_7_recovery_threshold(),
    )
    .expect("slot-a share materials");
    let support_a = [
        materials_a[0].clone(),
        materials_a[3].clone(),
        materials_a[6].clone(),
    ];
    let (recovered_surface_a, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&support_a)
            .expect("slot-a recovered full extractable surface");
    let recovered_header_a = recovered_publication_frontier_header(&recovered_surface_a);
    let frontier_a = build_publication_frontier(&recovered_header_a, None)
        .expect("slot-a recovered publication frontier");
    ioi_types::app::verify_publication_frontier(&recovered_header_a, &frontier_a, None)
        .expect("slot-a recovered publication frontier should verify");

    let mut base_header_b = sample_block_header();
    base_header_b.height = header_a.height + 1;
    base_header_b.view = header_a.view + 1;
    base_header_b.parent_hash =
        canonical_block_commitment_hash(&header_a).expect("slot-a block commitment hash");
    base_header_b.parent_state_root = header_a.state_root.clone();
    base_header_b.timestamp = header_a.timestamp + 1;
    base_header_b.timestamp_ms = header_a.timestamp_ms + 1_000;
    base_header_b.parent_qc.height = header_a.height;
    base_header_b.parent_qc.view = header_a.view;
    base_header_b.parent_qc.block_hash = base_header_b.parent_hash;
    let (header_b, transactions_b) =
        sample_block_header_with_ordered_transactions_from_header(base_header_b, 0x65);
    let materials_b = build_experimental_multi_witness_recovery_share_materials(
        &header_b,
        &transactions_b,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_7_share_count(),
        sample_gf256_3_of_7_recovery_threshold(),
    )
    .expect("slot-b share materials");
    let support_b = [
        materials_b[0].clone(),
        materials_b[3].clone(),
        materials_b[6].clone(),
    ];
    let (recovered_surface_b, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&support_b)
            .expect("slot-b recovered full extractable surface");
    let recovered_header_b = recovered_publication_frontier_header(&recovered_surface_b);
    let frontier_b = build_publication_frontier(&recovered_header_b, Some(&frontier_a))
        .expect("slot-b recovered publication frontier");
    ioi_types::app::verify_publication_frontier(
        &recovered_header_b,
        &frontier_b,
        Some(&frontier_a),
    )
    .expect("slot-b recovered publication frontier should verify");

    assert_eq!(frontier_a.height, 1);
    assert_eq!(frontier_a.parent_frontier_hash, [0u8; 32]);
    assert_eq!(frontier_b.height, 2);
    assert_eq!(frontier_b.counter, frontier_a.counter + 1);
    assert_eq!(
        frontier_b.parent_frontier_hash,
        ioi_types::app::canonical_publication_frontier_hash(&frontier_a)
            .expect("slot-a publication frontier hash")
    );
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_four_of_six_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5f);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xd1u8; 32],
        [0xd2u8; 32],
        [0xd3u8; 32],
        [0xd4u8; 32],
        [0xd5u8; 32],
        [0xd6u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_4_of_6_share_count(),
        sample_gf256_4_of_6_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[2].clone(),
        materials[4].clone(),
        materials[5].clone(),
    ])
    .expect("payload should reconstruct from four of six gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_four_of_seven_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x62);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0x11u8; 32],
        [0x12u8; 32],
        [0x13u8; 32],
        [0x14u8; 32],
        [0x15u8; 32],
        [0x16u8; 32],
        [0x17u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_4_of_7_share_count(),
        sample_gf256_4_of_7_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[2].clone(),
        materials[4].clone(),
        materials[6].clone(),
    ])
    .expect("payload should reconstruct from four of seven gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_commitments_change_with_transaction_bytes() {
    let (header_a, transactions_a) = sample_block_header_with_ordered_transactions(0x53);
    let (header_b, transactions_b) = sample_block_header_with_ordered_transactions(0x54);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x68u8; 32], [0x69u8; 32], [0x6au8; 32], [0x6bu8; 32]]);
    let materials_a = build_experimental_multi_witness_recovery_share_materials(
        &header_a,
        &transactions_a,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("share materials a");
    let materials_b = build_experimental_multi_witness_recovery_share_materials(
        &header_b,
        &transactions_b,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("share materials b");

    let commitments_a = materials_a
        .iter()
        .map(|material| material.share_commitment_hash)
        .collect::<Vec<_>>();
    let commitments_b = materials_b
        .iter()
        .map(|material| material.share_commitment_hash)
        .collect::<Vec<_>>();
    let shard_bytes_a = materials_a
        .iter()
        .map(|material| material.material_bytes.clone())
        .collect::<Vec<_>>();
    let shard_bytes_b = materials_b
        .iter()
        .map(|material| material.material_bytes.clone())
        .collect::<Vec<_>>();

    assert_ne!(commitments_a, commitments_b);
    assert_ne!(shard_bytes_a, shard_bytes_b);
}

#[test]
fn experimental_multi_witness_recovery_share_material_coded_family_subset_conformance_holds_across_bounded_geometries(
) {
    for (transaction_seed, manifest_seed, share_count, recovery_threshold) in [
        (0x57, 0x63, 3, 2),
        (0x59, 0x69, 4, 3),
        (0x5a, 0x71, 4, 2),
        (0x5c, 0xa1, 5, 3),
        (0x5d, 0xb1, 7, 3),
        (0x5f, 0xd1, 6, 4),
        (0x62, 0x11, 7, 4),
    ] {
        assert_coded_recovery_family_subset_conformance_case(
            transaction_seed,
            manifest_seed,
            share_count,
            recovery_threshold,
        );
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_coded_family_commitments_are_deterministic_and_input_sensitive(
) {
    for (
        transaction_seed,
        manifest_seed,
        alternate_manifest_seed,
        share_count,
        recovery_threshold,
    ) in [
        (0x49, 0x52, 0x62, 3, 2),
        (0x4d, 0x56, 0x66, 4, 3),
        (0x53, 0x68, 0x78, 4, 2),
        (0x5d, 0xb1, 0xc1, 7, 3),
        (0x62, 0x11, 0x21, 7, 4),
    ] {
        assert_coded_recovery_family_commitment_determinism_case(
            transaction_seed,
            manifest_seed,
            alternate_manifest_seed,
            share_count,
            recovery_threshold,
        );
    }
}

#[test]
fn experimental_multi_witness_recovery_binding_assignments_build_for_gf256_shape() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x58);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x81u8; 32], [0x82u8; 32], [0x83u8; 32], [0x84u8; 32]]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_gf256_2_of_4_share_count(),
    )
    .expect("derive witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("build multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build multi-witness recovery bindings");
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
    let distinct_manifests = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_share_commitments = binding_assignments
        .iter()
        .map(|assignment| assignment.recovery_binding.share_commitment_hash)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        capsule.coding,
        gf256_recovery_coding(
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
    );
    assert_eq!(
        capsule.coding.recovery_threshold,
        sample_gf256_2_of_4_recovery_threshold()
    );
    assert_eq!(
        binding_assignments.len(),
        usize::from(sample_gf256_2_of_4_share_count())
    );
    assert_eq!(distinct_manifests.len(), binding_assignments.len());
    assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
    assert!(binding_assignments.iter().all(|assignment| {
        assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
    }));
}

#[test]
fn experimental_multi_witness_recovery_binding_assignments_build_for_three_of_five_gf256_shape() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5d);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xb1u8; 32],
        [0xb2u8; 32],
        [0xb3u8; 32],
        [0xb4u8; 32],
        [0xb5u8; 32],
    ]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_gf256_3_of_5_share_count(),
    )
    .expect("derive witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_gf256_3_of_5_recovery_threshold(),
    )
    .expect("build multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build multi-witness recovery bindings");
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
    let distinct_manifests = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_share_commitments = binding_assignments
        .iter()
        .map(|assignment| assignment.recovery_binding.share_commitment_hash)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        capsule.coding,
        gf256_recovery_coding(
            sample_gf256_3_of_5_share_count(),
            sample_gf256_3_of_5_recovery_threshold(),
        )
    );
    assert_eq!(
        capsule.coding.recovery_threshold,
        sample_gf256_3_of_5_recovery_threshold()
    );
    assert_eq!(
        binding_assignments.len(),
        usize::from(sample_gf256_3_of_5_share_count())
    );
    assert_eq!(distinct_manifests.len(), binding_assignments.len());
    assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
    assert!(binding_assignments.iter().all(|assignment| {
        assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
    }));
}

#[test]
fn experimental_multi_witness_recovery_binding_assignments_build_for_four_of_six_gf256_shape() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x60);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xe1u8; 32],
        [0xe2u8; 32],
        [0xe3u8; 32],
        [0xe4u8; 32],
        [0xe5u8; 32],
        [0xe6u8; 32],
    ]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_gf256_4_of_6_share_count(),
    )
    .expect("derive witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_gf256_4_of_6_recovery_threshold(),
    )
    .expect("build multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build multi-witness recovery bindings");
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
    let distinct_manifests = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_share_commitments = binding_assignments
        .iter()
        .map(|assignment| assignment.recovery_binding.share_commitment_hash)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        capsule.coding,
        gf256_recovery_coding(
            sample_gf256_4_of_6_share_count(),
            sample_gf256_4_of_6_recovery_threshold(),
        )
    );
    assert_eq!(
        capsule.coding.recovery_threshold,
        sample_gf256_4_of_6_recovery_threshold()
    );
    assert_eq!(
        binding_assignments.len(),
        usize::from(sample_gf256_4_of_6_share_count())
    );
    assert_eq!(distinct_manifests.len(), binding_assignments.len());
    assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
    assert!(binding_assignments.iter().all(|assignment| {
        assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
    }));
}

#[test]
fn experimental_multi_witness_recovery_binding_assignments_build_for_four_of_seven_gf256_shape() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x63);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0x21u8; 32],
        [0x22u8; 32],
        [0x23u8; 32],
        [0x24u8; 32],
        [0x25u8; 32],
        [0x26u8; 32],
        [0x27u8; 32],
    ]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_gf256_4_of_7_share_count(),
    )
    .expect("derive witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_gf256_4_of_7_recovery_threshold(),
    )
    .expect("build multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build multi-witness recovery bindings");
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
    let distinct_manifests = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_share_commitments = binding_assignments
        .iter()
        .map(|assignment| assignment.recovery_binding.share_commitment_hash)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        capsule.coding,
        gf256_recovery_coding(
            sample_gf256_4_of_7_share_count(),
            sample_gf256_4_of_7_recovery_threshold(),
        )
    );
    assert_eq!(
        capsule.coding.recovery_threshold,
        sample_gf256_4_of_7_recovery_threshold()
    );
    assert_eq!(
        binding_assignments.len(),
        usize::from(sample_gf256_4_of_7_share_count())
    );
    assert_eq!(distinct_manifests.len(), binding_assignments.len());
    assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
    assert!(binding_assignments.iter().all(|assignment| {
        assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
    }));
}

#[test]
fn experimental_multi_witness_recovery_share_material_stays_transparent_outside_coded_shapes() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0x81u8; 32],
        [0x82u8; 32],
        [0x83u8; 32],
        [0x84u8; 32],
        [0x85u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        5,
        5,
    )
    .expect("share materials");

    assert_eq!(materials.len(), 5);
    assert!(materials.iter().all(|material| {
        material.coding.family == RecoveryCodingFamily::TransparentCommittedSurfaceV1
    }));
}

#[test]
fn experimental_multi_witness_recovery_share_material_rejects_tampered_material_bytes() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![[0x71u8; 32], [0x72u8; 32], [0x73u8; 32]]);
    let mut material = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        3,
        2,
    )
    .expect("share materials")
    .into_iter()
    .next()
    .expect("first share material");
    material.material_bytes[0] ^= 0xFF;

    let error = verify_experimental_multi_witness_recovery_share_material(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        &material,
    )
    .expect_err("tampered share material should fail verification");

    assert!(
        error
            .to_string()
            .contains("deterministic committed-surface materialization"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn canonicalize_observer_sealed_finality_proof_rewrites_invalid_close_into_abort() {
    let header = sample_block_header();
    let policy = AsymptotePolicy {
        epoch: 9,
        observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
        observer_challenge_window_ms: 500,
        ..Default::default()
    };
    let assignment = ioi_types::app::AsymptoteObserverAssignment {
        epoch: 9,
        producer_account_id: header.producer_account_id,
        height: header.height,
        view: header.view,
        round: 0,
        observer_account_id: AccountId([42u8; 32]),
    };
    let transcripts = vec![AsymptoteObserverTranscript {
        statement: AsymptoteObserverStatement {
            epoch: 9,
            assignment: assignment.clone(),
            block_hash: [50u8; 32],
            guardian_manifest_hash: [51u8; 32],
            guardian_decision_hash: [52u8; 32],
            guardian_counter: 53,
            guardian_trace_hash: [54u8; 32],
            guardian_measurement_root: [55u8; 32],
            guardian_checkpoint_root: [56u8; 32],
            verdict: ioi_types::app::AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [57u8; 32],
        },
        guardian_certificate: header
            .guardian_certificate
            .clone()
            .expect("sample header must carry guardian certificate"),
    }];
    let assignments_hash =
        canonical_asymptote_observer_assignments_hash(&[assignment]).expect("assignment hash");
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&transcripts).expect("transcript root");
    let empty_challenges: Vec<AsymptoteObserverChallenge> = Vec::new();
    let empty_challenges_root = canonical_asymptote_observer_challenges_hash(&empty_challenges)
        .expect("empty challenge root");
    let invalid_close = AsymptoteObserverCanonicalClose {
        epoch: 9,
        height: header.height,
        view: header.view,
        assignments_hash,
        transcripts_root,
        challenges_root: empty_challenges_root,
        transcript_count: 1,
        challenge_count: 1,
        challenge_cutoff_timestamp_ms: header.timestamp_ms_or_legacy().saturating_add(500),
    };
    let mut proof = SealedFinalityProof {
        epoch: 9,
        finality_tier: ioi_types::app::FinalityTier::SealedFinal,
        collapse_state: ioi_types::app::CollapseState::SealedFinal,
        guardian_manifest_hash: [58u8; 32],
        guardian_decision_hash: [59u8; 32],
        guardian_counter: 60,
        guardian_trace_hash: [61u8; 32],
        guardian_measurement_root: [62u8; 32],
        policy_hash: [63u8; 32],
        witness_certificates: Vec::new(),
        observer_certificates: Vec::new(),
        observer_close_certificate: None,
        observer_transcripts: transcripts.clone(),
        observer_challenges: Vec::new(),
        observer_transcript_commitment: Some(AsymptoteObserverTranscriptCommitment {
            epoch: 9,
            height: header.height,
            view: header.view,
            assignments_hash,
            transcripts_root,
            transcript_count: 1,
        }),
        observer_challenge_commitment: Some(AsymptoteObserverChallengeCommitment {
            epoch: 9,
            height: header.height,
            view: header.view,
            challenges_root: empty_challenges_root,
            challenge_count: 0,
        }),
        observer_canonical_close: Some(invalid_close.clone()),
        observer_canonical_abort: None,
        veto_proofs: Vec::new(),
        divergence_signals: Vec::new(),
        proof_signature: SignatureProof::default(),
    };

    let artifacts =
        canonicalize_observer_sealed_finality_proof(&header, &policy, [64u8; 32], &mut proof)
            .expect("canonicalization should succeed")
            .expect("invalid close should still yield canonical artifacts");

    assert_eq!(proof.finality_tier, ioi_types::app::FinalityTier::BaseFinal);
    assert_eq!(proof.collapse_state, ioi_types::app::CollapseState::Abort);
    assert!(proof.observer_canonical_close.is_none());
    assert!(proof.observer_canonical_abort.is_some());
    let invalid_close_challenge = proof
        .observer_challenges
        .iter()
        .find(|challenge| challenge.kind == AsymptoteObserverChallengeKind::InvalidCanonicalClose)
        .expect("invalid close challenge inserted");
    assert_eq!(
        invalid_close_challenge.canonical_close.as_ref(),
        Some(&invalid_close)
    );
    assert_eq!(artifacts.canonical_close, None);
    assert!(artifacts.canonical_abort.is_some());
}

#[tokio::test]
async fn publish_canonical_observer_abort_artifacts_enqueues_transcript_challenge_and_abort() {
    let assignment = ioi_types::app::AsymptoteObserverAssignment {
        epoch: 9,
        producer_account_id: AccountId([21u8; 32]),
        height: 11,
        view: 4,
        round: 0,
        observer_account_id: AccountId([22u8; 32]),
    };
    let observation_request = ioi_types::app::AsymptoteObserverObservationRequest {
        epoch: 9,
        assignment: assignment.clone(),
        block_hash: [23u8; 32],
        guardian_manifest_hash: [24u8; 32],
        guardian_decision_hash: [25u8; 32],
        guardian_counter: 26,
        guardian_trace_hash: [27u8; 32],
        guardian_measurement_root: [28u8; 32],
        guardian_checkpoint_root: [29u8; 32],
    };
    let transcript = AsymptoteObserverTranscript {
        statement: AsymptoteObserverStatement {
            epoch: 9,
            assignment: assignment.clone(),
            block_hash: [23u8; 32],
            guardian_manifest_hash: [24u8; 32],
            guardian_decision_hash: [25u8; 32],
            guardian_counter: 26,
            guardian_trace_hash: [27u8; 32],
            guardian_measurement_root: [28u8; 32],
            guardian_checkpoint_root: [29u8; 32],
            verdict: ioi_types::app::AsymptoteObserverVerdict::Ok,
            veto_kind: None,
            evidence_hash: [30u8; 32],
        },
        guardian_certificate: sample_block_header()
            .guardian_certificate
            .expect("sample header must carry guardian certificate"),
    };
    let challenge = AsymptoteObserverChallenge {
        challenge_id: [31u8; 32],
        epoch: 9,
        height: 11,
        view: 4,
        kind: ioi_types::app::AsymptoteObserverChallengeKind::TranscriptMismatch,
        challenger_account_id: AccountId([32u8; 32]),
        assignment: Some(assignment.clone()),
        observation_request: Some(observation_request),
        transcript: Some(transcript.clone()),
        canonical_close: None,
        evidence_hash: [33u8; 32],
        details: "observer recovered a malformed request".to_string(),
    };
    let assignments_hash =
        canonical_asymptote_observer_assignments_hash(&[assignment]).expect("assignment hash");
    let transcripts_root = canonical_asymptote_observer_transcripts_hash(&[transcript.clone()])
        .expect("transcript root");
    let challenges_root =
        canonical_asymptote_observer_challenges_hash(&[challenge.clone()]).expect("challenge root");
    let artifacts = CanonicalObserverPublicationArtifacts {
        transcripts: vec![transcript],
        challenges: vec![challenge],
        transcript_commitment: AsymptoteObserverTranscriptCommitment {
            epoch: 9,
            height: 11,
            view: 4,
            assignments_hash,
            transcripts_root,
            transcript_count: 1,
        },
        challenge_commitment: AsymptoteObserverChallengeCommitment {
            epoch: 9,
            height: 11,
            view: 4,
            challenges_root,
            challenge_count: 1,
        },
        canonical_close: None,
        canonical_abort: Some(AsymptoteObserverCanonicalAbort {
            epoch: 9,
            height: 11,
            view: 4,
            assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: 1,
            challenge_count: 1,
            challenge_cutoff_timestamp_ms: 1_700_000_000_500,
        }),
    };
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(TestWorkloadClient),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_canonical_observer_artifacts(&publisher, &artifacts)
        .await
        .expect("artifact publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 5);

    let mut published_bundle = None;
    let methods = selected
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_canonical_order_artifact_bundle@v1" {
                        published_bundle = Some(
                            codec::from_bytes_canonical::<CanonicalOrderPublicationBundle>(&params)
                                .expect("decode published canonical-order bundle"),
                        );
                    }
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec![
            "publish_asymptote_observer_transcript@v1".to_string(),
            "publish_asymptote_observer_transcript_commitment@v1".to_string(),
            "report_asymptote_observer_challenge@v1".to_string(),
            "publish_asymptote_observer_challenge_commitment@v1".to_string(),
            "publish_asymptote_observer_canonical_abort@v1".to_string(),
        ]
    );

    for _ in 0..5 {
        consensus_kick_rx
            .try_recv()
            .expect("publication should kick consensus for each enqueued tx");
    }
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "expected exactly one kick per published artifact tx"
    );
}

#[tokio::test]
async fn publish_canonical_order_artifacts_enqueues_bulletin_surface_and_certificate() {
    let base_header = sample_block_header();
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([41u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![1],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([42u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![2],
        },
        signature_proof: SignatureProof::default(),
    }));
    let ordered_transactions =
        ioi_types::app::canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
            .expect("canonicalized transactions");
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().expect("tx hash"))
        .collect();

    let mut header = base_header;
    header.transactions_root = ioi_types::app::canonical_transaction_root_from_hashes(&tx_hashes)
        .expect("transactions root");
    header.canonical_order_certificate = Some(
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .expect("build committed-surface certificate"),
    );

    let artifacts = build_canonical_order_publication_artifacts(&header, &ordered_transactions)
        .expect("build publication artifacts");
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(TestWorkloadClient),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_canonical_order_artifacts(&publisher, &artifacts)
        .await
        .expect("artifact publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 1);

    let mut published_bundle = None;
    let methods = selected
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_canonical_order_artifact_bundle@v1" {
                        published_bundle = Some(
                            codec::from_bytes_canonical::<CanonicalOrderPublicationBundle>(&params)
                                .expect("decode published canonical-order bundle"),
                        );
                    }
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec!["publish_aft_canonical_order_artifact_bundle@v1".to_string()]
    );
    let published_bundle = published_bundle.expect("published bundle captured");
    assert_eq!(
        published_bundle
            .bulletin_retrievability_profile
            .bulletin_commitment_hash,
        published_bundle
            .bulletin_availability_certificate
            .bulletin_commitment_hash
    );
    assert_eq!(
        published_bundle.bulletin_shard_manifest.entry_count,
        published_bundle.bulletin_commitment.entry_count
    );
    assert_eq!(
        published_bundle
            .bulletin_custody_receipt
            .bulletin_shard_manifest_hash,
        ioi_types::app::canonical_bulletin_shard_manifest_hash(
            &published_bundle.bulletin_shard_manifest,
        )
        .expect("hash published shard manifest")
    );

    for _ in 0..1 {
        consensus_kick_rx
            .try_recv()
            .expect("publication should kick consensus for each enqueued tx");
    }
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "expected exactly one kick per published artifact tx"
    );
}

#[tokio::test]
async fn publish_canonical_order_abort_enqueues_abort_tx() {
    let header = sample_block_header();
    let artifacts = build_canonical_order_publication_artifacts(&header, &[])
        .expect("build publication artifacts");
    assert!(artifacts.bundle.is_none());
    let abort = artifacts
        .canonical_abort
        .as_ref()
        .expect("missing certificate must derive ordering abort");
    assert_eq!(abort.height, header.height);

    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(TestWorkloadClient),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_canonical_order_artifacts(&publisher, &artifacts)
        .await
        .expect("abort publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 1);

    let methods = selected
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id, method, ..
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec!["publish_aft_canonical_order_abort@v1".to_string()]
    );
    consensus_kick_rx
        .try_recv()
        .expect("abort publication should kick consensus");
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "expected exactly one kick for the ordering abort publication"
    );
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_enqueues_capsule_then_witness_certificate_when_capsule_is_missing(
) {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let expected_receipt = build_experimental_recovery_scaffold_share_receipt(
        &block.header,
        &derive_recovery_witness_certificate_for_header(
            &block.header,
            block
                .header
                .guardian_certificate
                .as_ref()
                .expect("guardian certificate"),
        )
        .expect("derive recovery witness certificate")
        .expect("recovery witness certificate"),
    )
    .expect("build recovery receipt");
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient::default()),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("recovery publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 3);

    let mut methods = Vec::new();
    let mut published_receipt = None;
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovery_share_receipt@v1" {
                        published_receipt = Some(
                            codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                .expect("decode recovery share receipt"),
                        );
                    }
                    methods.push(method);
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        }
    }

    assert_eq!(
        methods,
        vec![
            "publish_aft_recovery_capsule@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
        ]
    );
    assert_eq!(published_receipt, Some(expected_receipt));
    for _ in 0..3 {
        consensus_kick_rx
            .try_recv()
            .expect("recovery publication should kick consensus");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
    assert_eq!(scaffold.capsule.coding.recovery_threshold, 1);
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_enqueues_only_witness_certificate_and_receipt_when_capsule_matches(
) {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let expected_receipt = build_experimental_recovery_scaffold_share_receipt(
        &block.header,
        &derive_recovery_witness_certificate_for_header(
            &block.header,
            block
                .header
                .guardian_certificate
                .as_ref()
                .expect("guardian certificate"),
        )
        .expect("derive recovery witness certificate")
        .expect("recovery witness certificate"),
    )
    .expect("build recovery receipt");
    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
    );
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("recovery publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 2);

    let mut methods = Vec::new();
    let mut published_receipt = None;
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovery_share_receipt@v1" {
                        published_receipt = Some(
                            codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                .expect("decode recovery share receipt"),
                        );
                    }
                    methods.push(method);
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        }
    }

    assert_eq!(
        methods,
        vec![
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
        ]
    );
    assert_eq!(published_receipt, Some(expected_receipt));
    for _ in 0..2 {
        consensus_kick_rx
            .try_recv()
            .expect("recovery publication should kick consensus");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_skips_receipt_when_missing_share_exists() {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
    );
    raw_state.insert(
        aft_missing_recovery_share_key(block.header.height, &[0x41u8; 32]),
        codec::to_bytes_canonical(&ioi_types::app::MissingRecoveryShare {
            height: block.header.height,
            witness_manifest_hash: [0x41u8; 32],
            recovery_capsule_hash: scaffold
                .recovery_binding()
                .expect("recovery binding")
                .recovery_capsule_hash,
            recovery_window_close_ms: scaffold.capsule.recovery_window_close_ms,
        })
        .expect("encode missing share"),
    );
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("recovery publication should succeed");

    let methods = publisher
        .tx_pool
        .select_transactions(8)
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id, method, ..
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec!["publish_aft_recovery_witness_certificate@v1".to_string()]
    );
    consensus_kick_rx
        .try_recv()
        .expect("recovery publication should kick consensus");
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_enqueues_only_witness_certificate_when_capsule_matches(
) {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&scaffold.capsule).expect("encode recovery capsule"),
    );
    raw_state.insert(
        aft_recovery_share_receipt_key(
            block.header.height,
            &[0x41u8; 32],
            &canonical_block_commitment_hash(&block.header).expect("block commitment"),
        ),
        codec::to_bytes_canonical(
            &build_experimental_recovery_scaffold_share_receipt(
                &block.header,
                &derive_recovery_witness_certificate_for_header(
                    &block.header,
                    block
                        .header
                        .guardian_certificate
                        .as_ref()
                        .expect("guardian certificate"),
                )
                .expect("derive recovery witness certificate")
                .expect("recovery witness certificate"),
            )
            .expect("build recovery receipt"),
        )
        .expect("encode recovery receipt"),
    );
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("recovery publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 1);

    let methods = selected
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id, method, ..
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec!["publish_aft_recovery_witness_certificate@v1".to_string()]
    );
    consensus_kick_rx
        .try_recv()
        .expect("recovery publication should kick consensus");
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_recovery_artifacts_skips_when_capsule_is_mismatched() {
    let (block, scaffold) = sample_block_with_recovery_scaffold();
    let mismatched_capsule = RecoveryCapsule {
        payload_commitment_hash: [0x55u8; 32],
        ..scaffold.capsule
    };
    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&mismatched_capsule).expect("encode recovery capsule"),
    );
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_recovery_artifacts(&publisher, &block)
        .await
        .expect("mismatched capsule should be skipped, not rejected");

    assert!(
            publisher.tx_pool.select_transactions(8).is_empty(),
            "no publication tx should be enqueued when the published capsule mismatches the signed binding"
        );
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "skipped recovery publication should not kick consensus"
    );
}

#[tokio::test]
async fn publish_experimental_sealed_recovery_artifacts_enqueues_capsule_witness_certificates_and_receipts(
) {
    let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
    let expected_witnesses = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_receipts = block
        .header
        .sealed_finality_proof
        .as_ref()
        .expect("sealed finality proof")
        .witness_certificates
        .iter()
        .map(|witness_certificate| {
            let statement =
                ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
                    &block.header,
                    block
                        .header
                        .guardian_certificate
                        .as_ref()
                        .expect("guardian certificate"),
                    witness_certificate.recovery_binding.clone(),
                );
            let certificate = ioi_types::app::derive_recovery_witness_certificate(
                &statement,
                witness_certificate,
            )
            .expect("derive sealed recovery witness certificate")
            .expect("recovery witness certificate");
            build_recovery_share_receipt_for_header(&block.header, &certificate)
                .expect("build recovery share receipt")
        })
        .collect::<Vec<_>>();
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient::default()),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_sealed_recovery_artifacts(
        &publisher,
        &block,
        Some(&capsule),
        &binding_assignments,
    )
    .await
    .expect("sealed recovery publication should succeed");

    let selected = publisher.tx_pool.select_transactions(16);
    assert_eq!(
        selected.len(),
        1 + 2 * usize::from(sample_parity_family_share_count())
    );

    let mut methods = Vec::new();
    let mut published_receipts = Vec::new();
    let mut published_witnesses = std::collections::BTreeSet::new();
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovery_witness_certificate@v1" {
                        let certificate = codec::from_bytes_canonical::<
                            ioi_types::app::RecoveryWitnessCertificate,
                        >(&params)
                        .expect("decode recovery witness certificate");
                        published_witnesses.insert(certificate.witness_manifest_hash);
                    }
                    if method == "publish_aft_recovery_share_receipt@v1" {
                        published_receipts.push(
                            codec::from_bytes_canonical::<RecoveryShareReceipt>(&params)
                                .expect("decode recovery share receipt"),
                        );
                    }
                    methods.push(method);
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        }
    }

    assert_eq!(
        methods,
        vec![
            "publish_aft_recovery_capsule@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
        ]
    );
    assert_eq!(published_witnesses, expected_witnesses);
    assert_eq!(published_receipts, expected_receipts);
    for _ in 0..(1 + 2 * usize::from(sample_parity_family_share_count())) {
        consensus_kick_rx
            .try_recv()
            .expect("sealed recovery publication should kick consensus");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_sealed_recovery_artifacts_skips_when_a_witness_binding_is_tampered() {
    let (mut block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
    block
        .header
        .sealed_finality_proof
        .as_mut()
        .expect("sealed finality proof")
        .witness_certificates[0]
        .recovery_binding
        .as_mut()
        .expect("recovery binding")
        .share_commitment_hash[0] ^= 0xff;
    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient::default()),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_sealed_recovery_artifacts(
        &publisher,
        &block,
        Some(&capsule),
        &binding_assignments,
    )
    .await
    .expect("tampered sealed recovery publication should be skipped, not rejected");

    assert!(
        publisher.tx_pool.select_transactions(16).is_empty(),
        "no publication tx should be enqueued when one sealed witness binding is tampered"
    );
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "skipped sealed recovery publication should not kick consensus"
    );
}

#[tokio::test]
async fn publish_experimental_locally_held_recovery_share_materials_enqueues_public_reveals_that_reconstruct_payload(
) {
    let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x91u8; 32], [0x92u8; 32], [0x93u8; 32], [0x94u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &block.header,
        &block.transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_parity_family_share_count(),
        sample_parity_family_recovery_threshold(),
    )
    .expect("recovery share materials");
    let signer = MockRecoveryRevealSigner {
        materials: materials
            .iter()
            .cloned()
            .map(|material| {
                (
                    (
                        material.witness_manifest_hash,
                        material.share_commitment_hash,
                    ),
                    material,
                )
            })
            .collect(),
    };

    let mut raw_state = BTreeMap::new();
    raw_state.insert(
        aft_recovery_capsule_key(block.header.height),
        codec::to_bytes_canonical(&capsule).expect("encode recovery capsule"),
    );
    for witness_certificate in &block
        .header
        .sealed_finality_proof
        .as_ref()
        .expect("sealed finality proof")
        .witness_certificates
    {
        let statement = ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
            &block.header,
            block
                .header
                .guardian_certificate
                .as_ref()
                .expect("guardian certificate"),
            witness_certificate.recovery_binding.clone(),
        );
        let certificate =
            ioi_types::app::derive_recovery_witness_certificate(&statement, witness_certificate)
                .expect("derive recovery witness certificate")
                .expect("recovery witness certificate");
        let receipt = build_recovery_share_receipt_for_header(&block.header, &certificate)
            .expect("recovery share receipt");
        raw_state.insert(
            ioi_types::app::aft_recovery_witness_certificate_key(
                certificate.height,
                &certificate.witness_manifest_hash,
            ),
            codec::to_bytes_canonical(&certificate).expect("encode recovery witness"),
        );
        raw_state.insert(
            aft_recovery_share_receipt_key(
                receipt.height,
                &receipt.witness_manifest_hash,
                &receipt.block_commitment_hash,
            ),
            codec::to_bytes_canonical(&receipt).expect("encode recovery share receipt"),
        );
    }

    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    let loaded_materials = publish_experimental_locally_held_recovery_share_materials(
        &publisher,
        &signer,
        &block,
        &witness_seed,
        &witness_set,
        0,
        &binding_assignments,
    )
    .await
    .expect("recovery share material publication should succeed");
    assert_eq!(loaded_materials, materials);

    let selected = publisher.tx_pool.select_transactions(16);
    assert_eq!(
        selected.len(),
        usize::from(sample_parity_family_share_count())
    );

    let mut methods = Vec::new();
    let mut published_materials = Vec::new();
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovery_share_material@v1" {
                        published_materials.push(
                            codec::from_bytes_canonical::<RecoveryShareMaterial>(&params)
                                .expect("decode recovery share material"),
                        );
                    }
                    methods.push(method);
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        }
    }

    assert_eq!(
        methods,
        vec![
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
        ]
    );
    assert_eq!(published_materials, materials);

    let reconstructed =
        recover_recoverable_slot_payload_v3_from_share_materials(&published_materials[..3])
            .expect("payload should reconstruct from three published parity-family share reveals");
    let expected_certificate =
        build_committed_surface_canonical_order_certificate(&block.header, &block.transactions)
            .expect("canonical order certificate");
    let expected_payload = build_recoverable_slot_payload_v3(
        &block.header,
        &block.transactions,
        &expected_certificate,
    )
    .expect("recoverable slot payload");
    assert_eq!(reconstructed, expected_payload);

    for _ in 0..usize::from(sample_parity_family_share_count()) {
        consensus_kick_rx
            .try_recv()
            .expect("share-material publication should kick consensus");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_experimental_recovery_pipeline_enqueues_recovered_publication_bundle_after_receipts_and_reveals(
) {
    let (block, capsule, binding_assignments) = sample_block_with_sealed_recovery_bindings();
    let previous_canonical_collapse =
        sample_previous_canonical_collapse_object(block.header.height - 1, 0x74);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x91u8; 32], [0x92u8; 32], [0x93u8; 32], [0x94u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &block.header,
        &block.transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_parity_family_share_count(),
        sample_parity_family_recovery_threshold(),
    )
    .expect("recovery share materials");
    let signer = MockRecoveryRevealSigner {
        materials: materials
            .iter()
            .cloned()
            .map(|material| {
                (
                    (
                        material.witness_manifest_hash,
                        material.share_commitment_hash,
                    ),
                    material,
                )
            })
            .collect(),
    };

    let synthetic_recovered =
        build_recovered_publication_bundle(&materials).expect("synthetic recovered bundle");
    let (segment_start_height, segment_end_height) = archived_recovered_restart_page_range(
        synthetic_recovered.height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        recovered_consensus_header_stitch_window_budget(),
        recovered_consensus_header_stitch_segment_budget(),
    )
    .expect("current archived page range");
    let (previous_start_height, previous_end_height) = archived_recovered_restart_page_range(
        segment_end_height - 1,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        recovered_consensus_header_stitch_window_budget(),
        recovered_consensus_header_stitch_segment_budget(),
    )
    .expect("previous archived page range");
    let archived_profile = default_archived_recovered_history_profile()
        .expect("default archived recovered-history profile");
    let archived_activation =
        build_archived_recovered_history_profile_activation(&archived_profile, None, 1, None)
            .expect("default archived recovered-history profile activation");
    let mut raw_state = BTreeMap::new();
    let synthetic_start_height = previous_start_height.min(segment_start_height);
    let synthetic_bundles = (synthetic_start_height..segment_end_height)
        .map(|height| {
            (
                height,
                synthetic_recovered_publication_bundle_for_height(&synthetic_recovered, height),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for bundle in synthetic_bundles.values() {
        let recovered_key = aft_recovered_publication_bundle_key(
            bundle.height,
            &bundle.block_commitment_hash,
            &bundle.supporting_witness_manifest_hashes,
        )
        .expect("recovered publication bundle key");
        raw_state.insert(
            recovered_key,
            codec::to_bytes_canonical(bundle).expect("encode recovered publication bundle"),
        );
    }
    let previous_segment_bundles = (previous_start_height..=previous_end_height)
        .map(|height| {
            synthetic_bundles
                .get(&height)
                .cloned()
                .expect("synthetic previous-segment recovered bundle")
        })
        .collect::<Vec<_>>();
    let previous_segment = build_archived_recovered_history_segment(
        &previous_segment_bundles,
        None,
        None,
        &archived_profile,
        &archived_activation,
    )
    .expect("previous archived recovered-history segment");
    let previous_page = synthetic_archived_restart_page(
        &previous_segment,
        synthetic_recovered.parent_block_commitment_hash,
    );
    let previous_checkpoint =
        build_archived_recovered_history_checkpoint(&previous_segment, &previous_page, None)
            .expect("previous archived recovered-history checkpoint");
    let active_validator_sets = validator_sets(&[(18, 1), (145, 1), (19, 1)]);
    let active_validator_set_bytes =
        write_validator_sets(&active_validator_sets).expect("encode active validator sets");
    let persisted_active_validator_sets = read_validator_sets(&active_validator_set_bytes)
        .expect("decode persisted active validator sets");
    raw_state.insert(
        aft_archived_recovered_history_segment_key(
            previous_segment.start_height,
            previous_segment.end_height,
        ),
        codec::to_bytes_canonical(&previous_segment)
            .expect("encode previous archived recovered-history segment"),
    );
    raw_state.insert(
        aft_archived_recovered_restart_page_key(&previous_page.segment_hash),
        codec::to_bytes_canonical(&previous_page)
            .expect("encode previous archived recovered restart page"),
    );
    raw_state.insert(
        aft_archived_recovered_history_checkpoint_key(
            previous_checkpoint.covered_start_height,
            previous_checkpoint.covered_end_height,
        ),
        codec::to_bytes_canonical(&previous_checkpoint)
            .expect("encode previous archived recovered-history checkpoint"),
    );
    raw_state.insert(
        ioi_types::app::AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY.to_vec(),
        codec::to_bytes_canonical(&previous_checkpoint)
            .expect("encode latest archived recovered-history checkpoint"),
    );
    raw_state.insert(VALIDATOR_SET_KEY.to_vec(), active_validator_set_bytes);

    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(StaticStateWorkloadClient { raw_state }),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_experimental_sealed_recovery_artifacts(
        &publisher,
        &block,
        Some(&capsule),
        &binding_assignments,
    )
    .await
    .expect("sealed recovery artifacts should publish");
    let published_materials = publish_experimental_locally_held_recovery_share_materials(
        &publisher,
        &signer,
        &block,
        &witness_seed,
        &witness_set,
        0,
        &binding_assignments,
    )
    .await
    .expect("share material publication should succeed");
    let recovered =
        publish_experimental_recovered_publication_bundle(&publisher, &published_materials)
            .await
            .expect("recovered publication bundle should publish")
            .expect("recovered publication bundle object");
    let (archived_profile, archived_activation) =
        ensure_archived_recovered_history_profile(&publisher)
            .await
            .expect("archived recovered-history profile should publish");
    let archived_segment = publish_archived_recovered_history_segment(
        &publisher,
        &recovered,
        &archived_profile,
        &archived_activation,
    )
    .await
    .expect("archived recovered-history segment should publish")
    .expect("archived recovered-history segment object");
    let support_materials =
        supporting_recovery_materials_for_recovered_bundle(&recovered, &published_materials)
            .expect("supporting recovery materials");
    let (recovered_full_surface, _, recovered_close, _) =
        recover_full_canonical_order_surface_from_share_materials(&support_materials)
            .expect("recover full canonical order surface");
    let canonical_collapse_object =
        ioi_types::app::derive_canonical_collapse_object_from_recovered_surface(
            &recovered_full_surface,
            &recovered_close,
            Some(&previous_canonical_collapse),
        )
        .expect("canonical collapse object from recovered surface");
    let archived_page = publish_archived_recovered_restart_page(
        &publisher,
        &archived_segment,
        &canonical_collapse_object,
        &recovered,
        &published_materials,
    )
    .await
    .expect("archived recovered restart page should publish")
    .expect("archived recovered restart page object");
    let archived_checkpoint = publish_archived_recovered_history_checkpoint(
        &publisher,
        &archived_segment,
        &archived_page,
    )
    .await
    .expect("archived recovered-history checkpoint should publish")
    .expect("archived recovered-history checkpoint object");
    let archived_retention_receipt = publish_archived_recovered_history_retention_receipt(
        &publisher,
        &archived_checkpoint,
        &archived_profile,
    )
    .await
    .expect("archived recovered-history retention receipt should publish")
    .expect("archived recovered-history retention receipt object");

    let selected = publisher.tx_pool.select_transactions(48);
    assert_eq!(
        selected.len(),
        3 * usize::from(sample_parity_family_share_count()) + 8
    );

    let mut methods = Vec::new();
    let mut published_recovered = None;
    let mut published_archived_profile = None;
    let mut published_archived_profile_activation = None;
    let mut published_archived_segment = None;
    let mut published_archived_page = None;
    let mut published_archived_checkpoint = None;
    let mut published_archived_retention_receipt = None;
    for tx in selected {
        match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    if method == "publish_aft_recovered_publication_bundle@v1" {
                        published_recovered = Some(
                            codec::from_bytes_canonical::<RecoveredPublicationBundle>(&params)
                                .expect("decode recovered publication bundle"),
                        );
                    } else if method == "publish_aft_archived_recovered_history_profile@v1" {
                        published_archived_profile = Some(
                            codec::from_bytes_canonical::<ArchivedRecoveredHistoryProfile>(&params)
                                .expect("decode archived recovered-history profile"),
                        );
                    } else if method
                        == "publish_aft_archived_recovered_history_profile_activation@v1"
                    {
                        published_archived_profile_activation =
                            Some(
                                codec::from_bytes_canonical::<
                                    ArchivedRecoveredHistoryProfileActivation,
                                >(&params)
                                .expect("decode archived recovered-history profile activation"),
                            );
                    } else if method == "publish_aft_archived_recovered_history_segment@v1" {
                        published_archived_segment = Some(
                            codec::from_bytes_canonical::<ArchivedRecoveredHistorySegment>(&params)
                                .expect("decode archived recovered-history segment"),
                        );
                    } else if method == "publish_aft_archived_recovered_restart_page@v1" {
                        published_archived_page = Some(
                            codec::from_bytes_canonical::<ArchivedRecoveredRestartPage>(&params)
                                .expect("decode archived recovered restart page"),
                        );
                    } else if method == "publish_aft_archived_recovered_history_checkpoint@v1" {
                        published_archived_checkpoint = Some(
                            codec::from_bytes_canonical::<ArchivedRecoveredHistoryCheckpoint>(
                                &params,
                            )
                            .expect("decode archived recovered-history checkpoint"),
                        );
                    } else if method
                        == "publish_aft_archived_recovered_history_retention_receipt@v1"
                    {
                        published_archived_retention_receipt =
                            Some(
                                codec::from_bytes_canonical::<
                                    ArchivedRecoveredHistoryRetentionReceipt,
                                >(&params)
                                .expect("decode archived recovered-history retention receipt"),
                            );
                    }
                    methods.push(method);
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        }
    }

    assert_eq!(
        methods,
        vec![
            "publish_aft_recovery_capsule@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_witness_certificate@v1".to_string(),
            "publish_aft_recovery_share_receipt@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovery_share_material@v1".to_string(),
            "publish_aft_recovered_publication_bundle@v1".to_string(),
            "publish_aft_archived_recovered_history_profile@v1".to_string(),
            "publish_aft_archived_recovered_history_profile_activation@v1".to_string(),
            "publish_aft_archived_recovered_history_segment@v1".to_string(),
            "publish_aft_archived_recovered_restart_page@v1".to_string(),
            "publish_aft_archived_recovered_history_checkpoint@v1".to_string(),
            "publish_aft_archived_recovered_history_retention_receipt@v1".to_string(),
        ]
    );
    assert_eq!(published_recovered, Some(recovered.clone()));
    assert_eq!(published_archived_profile, Some(archived_profile.clone()));
    assert_eq!(
        published_archived_profile_activation,
        Some(
            build_archived_recovered_history_profile_activation(&archived_profile, None, 1, None,)
                .expect("expected archived recovered-history profile activation")
        )
    );
    assert_eq!(published_archived_segment, Some(archived_segment.clone()));
    assert_eq!(published_archived_page, Some(archived_page.clone()));
    assert_eq!(
        published_archived_checkpoint,
        Some(archived_checkpoint.clone())
    );
    assert_eq!(
        published_archived_retention_receipt,
        Some(archived_retention_receipt.clone())
    );
    assert_eq!(
        recovered,
        build_recovered_publication_bundle(&materials).expect("expected recovered bundle")
    );
    let expected_archived_bundles = (segment_start_height..=segment_end_height)
        .map(|height| {
            if height == recovered.height {
                recovered.clone()
            } else {
                synthetic_bundles
                    .get(&height)
                    .cloned()
                    .expect("synthetic archived recovered-history bundle")
            }
        })
        .collect::<Vec<_>>();
    let expected_overlap_range = Some((
        segment_start_height.max(previous_segment.start_height),
        segment_end_height
            .saturating_sub(1)
            .min(previous_segment.end_height),
    ));
    assert_eq!(
        archived_segment,
        build_archived_recovered_history_segment(
            &expected_archived_bundles,
            Some(&previous_segment),
            expected_overlap_range,
            &archived_profile,
            &archived_activation,
        )
        .expect("expected archived recovered-history segment")
    );
    let expected_archived_page = build_archived_recovered_restart_page(
        &archived_segment,
        &[
            previous_page.restart_headers[usize::try_from(
                segment_start_height - previous_start_height,
            )
            .expect("overlap page offset")..]
                .to_vec(),
            vec![archived_page
                .restart_headers
                .last()
                .cloned()
                .expect("published archived restart page tip")],
        ]
        .concat(),
    )
    .expect("expected archived recovered restart page");
    assert_eq!(archived_page, expected_archived_page);
    let expected_archived_checkpoint = build_archived_recovered_history_checkpoint(
        &archived_segment,
        &archived_page,
        Some(&previous_checkpoint),
    )
    .expect("expected archived recovered-history checkpoint");
    assert_eq!(archived_checkpoint, expected_archived_checkpoint);
    let expected_archived_retention_receipt = build_archived_recovered_history_retention_receipt(
        &archived_checkpoint,
        canonical_validator_sets_hash(&persisted_active_validator_sets)
            .expect("validator set commitment hash"),
        archived_recovered_history_retained_through_height(&archived_checkpoint, &archived_profile)
            .expect("retained-through height from archived profile"),
    )
    .expect("expected archived recovered-history retention receipt");
    assert_eq!(
        archived_retention_receipt,
        expected_archived_retention_receipt
    );

    for _ in 0..(3 * usize::from(sample_parity_family_share_count()) + 8) {
        consensus_kick_rx
            .try_recv()
            .expect("publication should kick consensus for each enqueued tx");
    }
    assert!(consensus_kick_rx.try_recv().is_err());
}

#[tokio::test]
async fn publish_canonical_collapse_object_enqueues_collapse_tx() {
    let base_header = sample_block_header();
    let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([51u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_bulletin_commitment@v1".into(),
            params: vec![1],
        },
        signature_proof: SignatureProof::default(),
    }));
    let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([52u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".into(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
            params: vec![2],
        },
        signature_proof: SignatureProof::default(),
    }));
    let ordered_transactions =
        ioi_types::app::canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
            .expect("canonicalized transactions");
    let tx_hashes: Vec<[u8; 32]> = ordered_transactions
        .iter()
        .map(|tx| tx.hash().expect("tx hash"))
        .collect();

    let mut header = base_header;
    header.transactions_root = ioi_types::app::canonical_transaction_root_from_hashes(&tx_hashes)
        .expect("transactions root");
    header.canonical_order_certificate = Some(
        build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
            .expect("build committed-surface certificate"),
    );
    let collapse = ioi_types::app::derive_canonical_collapse_object(&header, &ordered_transactions)
        .expect("derive canonical collapse object");

    let (consensus_kick_tx, mut consensus_kick_rx) = mpsc::unbounded_channel();
    let publisher = GuardianRegistryPublisher {
        workload_client: Arc::new(TestWorkloadClient),
        tx_pool: Arc::new(Mempool::new()),
        consensus_kick_tx,
        nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
        local_keypair: libp2p::identity::Keypair::generate_ed25519(),
        chain_id: ChainId(1),
    };

    publish_canonical_collapse_object(&publisher, &collapse)
        .await
        .expect("collapse publication should succeed");

    let selected = publisher.tx_pool.select_transactions(8);
    assert_eq!(selected.len(), 1);

    let methods = selected
        .into_iter()
        .map(|tx| match tx {
            ChainTransaction::System(system_tx) => match system_tx.payload {
                SystemPayload::CallService {
                    service_id, method, ..
                } => {
                    assert_eq!(service_id, "guardian_registry");
                    method
                }
            },
            other => panic!("unexpected non-system publication tx: {other:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec!["publish_aft_canonical_collapse_object@v1".to_string()]
    );
    consensus_kick_rx
        .try_recv()
        .expect("collapse publication should kick consensus");
    assert!(
        consensus_kick_rx.try_recv().is_err(),
        "expected exactly one kick for the collapse publication"
    );
}
