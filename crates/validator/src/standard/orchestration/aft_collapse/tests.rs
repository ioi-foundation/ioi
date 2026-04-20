use super::*;
use async_trait::async_trait;
use ioi_api::app::ChainStatus;
use ioi_api::chain::QueryStateResponse;
use ioi_types::app::{
    canonical_collapse_commitment, canonical_collapse_commitment_hash_from_object,
    canonical_collapse_continuity_public_inputs, canonical_collapse_extension_certificate,
    canonical_collapse_recursive_proof_hash, canonical_collapse_succinct_mock_proof_bytes,
    set_canonical_collapse_archived_recovered_history_anchor, AccountId,
    CanonicalCollapseContinuityProofSystem, CanonicalCollapseExtensionCertificate,
    QuorumCertificate, SignatureSuite, StateAnchor, StateRoot,
};
use ioi_types::error::ChainError;
use std::any::Any;
use std::collections::BTreeMap;
use std::sync::{Mutex as StdMutex, OnceLock};
use tokio::sync::Mutex;

#[derive(Debug, Default)]
struct TestWorkloadClient {
    raw_state: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
}

#[async_trait]
impl WorkloadClientApi for TestWorkloadClient {
    async fn process_block(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_blocks_range(
        &self,
        _since: u64,
        _max_blocks: u32,
        _max_bytes: u32,
    ) -> std::result::Result<Vec<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_block_by_height(
        &self,
        _height: u64,
    ) -> std::result::Result<Option<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn check_transactions_at(
        &self,
        _anchor: StateAnchor,
        _expected_timestamp_secs: u64,
        _txs: Vec<ChainTransaction>,
    ) -> std::result::Result<Vec<std::result::Result<(), String>>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn query_state_at(
        &self,
        _root: StateRoot,
        _key: &[u8],
    ) -> std::result::Result<QueryStateResponse, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn query_raw_state(
        &self,
        key: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, ChainError> {
        Ok(self.raw_state.lock().await.get(key).cloned())
    }

    async fn prefix_scan(
        &self,
        _prefix: &[u8],
    ) -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_staked_validators(
        &self,
    ) -> std::result::Result<BTreeMap<AccountId, u64>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_genesis_status(&self) -> std::result::Result<bool, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn update_block_header(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(), ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn sample_block() -> Block<ChainTransaction> {
    let mut header = ioi_types::app::BlockHeader {
        height: 2,
        view: 5,
        parent_hash: [1u8; 32],
        parent_state_root: StateRoot(vec![2u8; 32]),
        state_root: StateRoot(vec![7u8; 32]),
        transactions_root: vec![8u8; 32],
        timestamp: 1_750_000_111,
        timestamp_ms: 1_750_000_111_000,
        gas_used: 33,
        validator_set: vec![vec![6u8; 32]],
        producer_account_id: AccountId([10u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [11u8; 32],
        producer_pubkey: vec![12u8; 32],
        signature: vec![13u8; 64],
        oracle_counter: 99,
        oracle_trace_hash: [14u8; 32],
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
    };
    header.canonical_order_certificate = Some(
        ioi_types::app::build_reference_canonical_order_certificate(&header, &[])
            .expect("reference order cert"),
    );

    Block {
        header,
        transactions: Vec::new(),
    }
}

fn bind_succinct_mock_continuity(collapse: &mut CanonicalCollapseObject) {
    let proof = &mut collapse.continuity_recursive_proof;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
        proof.previous_recursive_proof_hash,
    );
    proof.proof_system = CanonicalCollapseContinuityProofSystem::SuccinctSp1V1;
    proof.proof_bytes = canonical_collapse_succinct_mock_proof_bytes(&public_inputs)
        .expect("succinct mock proof bytes");
}

fn continuity_env_lock() -> &'static StdMutex<()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
}

#[test]
fn verify_canonical_collapse_backend_accepts_and_rejects_succinct_mock_proofs() {
    let mut collapse = CanonicalCollapseObject {
        height: 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [1u8; 32],
        resulting_state_root_hash: [2u8; 32],
    };
    ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, None)
        .expect("bind continuity");
    bind_succinct_mock_continuity(&mut collapse);

    verify_canonical_collapse_backend(&collapse).expect("succinct backend proof should verify");

    let mut mutated = collapse.clone();
    mutated.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
    assert!(verify_canonical_collapse_backend(&mutated).is_err());
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_accepts_matching_state() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [1u8; 32],
        resulting_state_root_hash: [2u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let loaded = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect("persisted collapse");
    assert_eq!(loaded, collapse);
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_accepts_matching_succinct_state() {
    let _guard = continuity_env_lock().lock().expect("continuity env lock");
    let previous_env = std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM").ok();
    std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", "succinct-sp1-v1");

    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [3u8; 32],
        resulting_state_root_hash: [4u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let loaded = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect("persisted succinct collapse");
    assert_eq!(loaded, collapse);

    if let Some(value) = previous_env {
        std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", value);
    } else {
        std::env::remove_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM");
    }
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_accepts_archived_anchor_upgrade() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [0x21u8; 32],
        resulting_state_root_hash: [0x22u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let derived = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let mut persisted = derived.clone();
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut persisted,
        [0x31u8; 32],
        [0x32u8; 32],
        [0x33u8; 32],
    )
    .expect("anchor upgrade");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&persisted).expect("encode collapse"),
    );

    let loaded = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect("persisted collapse");
    assert_eq!(loaded, persisted);
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_corrupted_succinct_previous_chain() {
    let _guard = continuity_env_lock().lock().expect("continuity env lock");
    let previous_env = std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM").ok();
    std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", "succinct-sp1-v1");

    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [5u8; 32],
        resulting_state_root_hash: [6u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let mut corrupted_previous = previous.clone();
    corrupted_previous.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;

    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&corrupted_previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("corrupted succinct predecessor chain should fail");
    assert!(
        error
            .to_string()
            .contains("persisted canonical collapse object does not match")
            || error.to_string().contains("continuity verification failed"),
        "unexpected error: {error}"
    );

    if let Some(value) = previous_env {
        std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", value);
    } else {
        std::env::remove_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM");
    }
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_mismatch() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [1u8; 32],
        resulting_state_root_hash: [2u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let mut collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    collapse.resulting_state_root_hash = [42u8; 32];
    ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, Some(&previous))
        .expect("rebind mutated collapse continuity");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("mismatched collapse should fail");
    assert!(
        error
            .to_string()
            .contains("persisted canonical collapse object does not match"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_missing_previous_link() {
    let block = sample_block();
    let collapse = CanonicalCollapseObject {
        height: block.header.height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [9u8; 32],
        resulting_state_root_hash: [10u8; 32],
    };
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("missing previous continuity link should fail");
    assert!(
        error
            .to_string()
            .contains("canonical collapse continuity requires a previous collapse object"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn resolve_live_aft_canonical_collapse_accepts_archived_anchor_upgrade() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [0x41u8; 32],
        resulting_state_root_hash: [0x42u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let mut persisted = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut persisted,
        [0x51u8; 32],
        [0x52u8; 32],
        [0x53u8; 32],
    )
    .expect("anchor upgrade");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&persisted).expect("encode collapse"),
    );

    let resolved = resolve_live_aft_canonical_collapse_for_block(
        ConsensusType::Aft,
        &client,
        Some(&previous),
        &block,
    )
    .await
    .expect("live collapse");
    assert_eq!(resolved, Some(persisted));
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_accepts_matching_succinct_backend_state() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [11u8; 32],
        resulting_state_root_hash: [12u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    bind_succinct_mock_continuity(&mut previous);
    block.header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let loaded = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect("persisted succinct collapse");
    assert_eq!(loaded, collapse);
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_invalid_succinct_backend_proof() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [13u8; 32],
        resulting_state_root_hash: [14u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    bind_succinct_mock_continuity(&mut previous);
    block.header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate =
        Some(CanonicalCollapseExtensionCertificate {
            predecessor_commitment: canonical_collapse_commitment(&previous),
            predecessor_recursive_proof_hash: canonical_collapse_recursive_proof_hash(
                &previous.continuity_recursive_proof,
            )
            .expect("predecessor proof hash"),
        });
    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let mut persisted = collapse.clone();
    persisted.continuity_recursive_proof.proof_bytes.reverse();
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&persisted).expect("encode collapse"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("invalid succinct proof should fail");
    assert!(
        error
            .to_string()
            .contains("persisted canonical collapse continuity verification failed")
            || error
                .to_string()
                .contains("canonical collapse continuity backend verification failed"),
        "unexpected error: {error}"
    );
}

#[test]
fn collapse_backed_aft_status_skips_speculative_tip() {
    let durable = sample_block();
    let mut speculative = durable.clone();
    speculative.header.height += 1;
    speculative.header.signature.clear();
    speculative.header.guardian_certificate = None;
    speculative.header.canonical_order_certificate = None;
    speculative.header.oracle_counter = 0;
    speculative.header.oracle_trace_hash = [0u8; 32];

    let base = ChainStatus {
        height: speculative.header.height,
        latest_timestamp: speculative.header.timestamp,
        total_transactions: 99,
        is_running: true,
        latest_timestamp_ms: speculative.header.timestamp_ms,
    };

    let derived = collapse_backed_aft_status(&base, [&speculative, &durable]);
    assert_eq!(derived.height, durable.header.height);
    assert_eq!(derived.latest_timestamp, durable.header.timestamp);
    assert_eq!(derived.latest_timestamp_ms, durable.header.timestamp_ms);
    assert_eq!(derived.total_transactions, base.total_transactions);
}

#[test]
fn collapse_backed_aft_status_returns_zero_when_no_durable_block_exists() {
    let mut speculative = sample_block();
    speculative.header.signature.clear();
    speculative.header.guardian_certificate = None;
    speculative.header.canonical_order_certificate = None;
    speculative.header.oracle_counter = 0;
    speculative.header.oracle_trace_hash = [0u8; 32];

    let base = ChainStatus {
        height: speculative.header.height,
        latest_timestamp: speculative.header.timestamp,
        total_transactions: 11,
        is_running: true,
        latest_timestamp_ms: speculative.header.timestamp_ms,
    };

    let derived = collapse_backed_aft_status(&base, [&speculative]);
    assert_eq!(derived.height, 0);
    assert_eq!(derived.latest_timestamp, 0);
    assert_eq!(derived.latest_timestamp_ms, 0);
    assert_eq!(derived.total_transactions, base.total_transactions);
    assert!(derived.is_running);
}
