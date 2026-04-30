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

