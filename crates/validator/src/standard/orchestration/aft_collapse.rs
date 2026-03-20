use anyhow::{anyhow, Result};
use ioi_api::app::{Block, ChainStatus, ChainTransaction};
use ioi_api::chain::WorkloadClientApi;
use ioi_api::consensus::CanonicalCollapseContinuityVerifier;
use ioi_types::app::{
    aft_canonical_collapse_object_key, canonical_collapse_continuity_public_inputs,
    derive_canonical_collapse_object, derive_canonical_collapse_object_with_previous,
    verify_canonical_collapse_continuity, CanonicalCollapseContinuityProofSystem,
    CanonicalCollapseObject,
};
use ioi_types::codec;
use ioi_types::config::ConsensusType;
use zk_driver_succinct::SuccinctDriver;

fn header_carries_aft_external_finality(block: &Block<ChainTransaction>) -> bool {
    let header = &block.header;
    !header.signature.is_empty()
        || header.guardian_certificate.is_some()
        || header.sealed_finality_proof.is_some()
        || header.canonical_order_certificate.is_some()
        || header.oracle_counter != 0
        || header.oracle_trace_hash != [0u8; 32]
}

fn header_carries_materialized_execution(block: &Block<ChainTransaction>) -> bool {
    let header = &block.header;
    header.timestamp_ms > 0
        || !header.state_root.0.is_empty()
        || !header.transactions_root.is_empty()
        || header.gas_used > 0
}

pub(crate) fn maybe_derive_persisted_canonical_collapse_object(
    block: &Block<ChainTransaction>,
) -> Result<Option<CanonicalCollapseObject>> {
    if !header_carries_aft_external_finality(block) || !header_carries_materialized_execution(block)
    {
        return Ok(None);
    }

    let collapse =
        derive_canonical_collapse_object(&block.header, &block.transactions).map_err(|error| {
            anyhow!(
                "failed to derive canonical collapse object for height {}: {error}",
                block.header.height
            )
        })?;
    Ok(Some(collapse))
}

pub(crate) async fn load_persisted_aft_canonical_collapse_object(
    workload_client: &dyn WorkloadClientApi,
    height: u64,
) -> Result<Option<CanonicalCollapseObject>> {
    let Some(raw) = workload_client
        .query_raw_state(&aft_canonical_collapse_object_key(height))
        .await
        .map_err(|error| {
            anyhow!("failed to load canonical collapse object from workload state: {error}")
        })?
    else {
        return Ok(None);
    };

    codec::from_bytes_canonical(&raw)
        .map(Some)
        .map_err(|error| anyhow!("failed to decode persisted canonical collapse object: {error}"))
}

pub(crate) async fn derive_expected_aft_canonical_collapse_for_block(
    workload_client: &dyn WorkloadClientApi,
    block: &Block<ChainTransaction>,
) -> Result<Option<CanonicalCollapseObject>> {
    if !header_carries_aft_external_finality(block) || !header_carries_materialized_execution(block)
    {
        return Ok(None);
    }

    let previous = if block.header.height <= 1 {
        None
    } else {
        load_persisted_aft_canonical_collapse_object(workload_client, block.header.height - 1)
            .await?
    };
    if let Some(previous) = previous.as_ref() {
        verify_canonical_collapse_backend(previous)?;
    }

    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        previous.as_ref(),
    )
    .map_err(|error| {
        anyhow!(
            "failed to derive canonical collapse object for height {}: {error}",
            block.header.height
        )
    })?;
    verify_canonical_collapse_continuity(&collapse, previous.as_ref()).map_err(|error| {
        anyhow!(
            "derived canonical collapse continuity verification failed for height {}: {}",
            block.header.height,
            error
        )
    })?;
    verify_canonical_collapse_backend(&collapse)?;
    Ok(Some(collapse))
}

pub(crate) async fn require_persisted_aft_canonical_collapse_for_block(
    workload_client: &dyn WorkloadClientApi,
    block: &Block<ChainTransaction>,
) -> Result<CanonicalCollapseObject> {
    let expected = derive_expected_aft_canonical_collapse_for_block(workload_client, block)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "AFT durable-state advancement requires a materialized canonical collapse object for height {}",
                block.header.height
            )
        })?;

    let Some(persisted) =
        load_persisted_aft_canonical_collapse_object(workload_client, block.header.height).await?
    else {
        return Err(anyhow!(
            "missing persisted canonical collapse object for AFT height {}",
            block.header.height
        ));
    };
    verify_persisted_aft_canonical_collapse_chain(workload_client, &persisted).await?;
    if persisted != expected {
        return Err(anyhow!(
            "persisted canonical collapse object does not match committed block surface at height {}",
            block.header.height
        ));
    }

    Ok(persisted)
}

pub(crate) async fn require_persisted_aft_canonical_collapse_if_needed(
    consensus_type: ConsensusType,
    workload_client: &dyn WorkloadClientApi,
    block: &Block<ChainTransaction>,
) -> Result<Option<CanonicalCollapseObject>> {
    if !matches!(consensus_type, ConsensusType::Aft) {
        return Ok(None);
    }

    require_persisted_aft_canonical_collapse_for_block(workload_client, block)
        .await
        .map(Some)
}

pub(crate) fn collapse_backed_aft_status<'a>(
    base: &ChainStatus,
    blocks_desc: impl IntoIterator<Item = &'a Block<ChainTransaction>>,
) -> ChainStatus {
    for block in blocks_desc {
        if maybe_derive_persisted_canonical_collapse_object(block)
            .ok()
            .flatten()
            .is_some()
        {
            let mut durable = base.clone();
            durable.height = block.header.height;
            durable.set_latest_timestamp_ms(block.header.timestamp_ms_or_legacy());
            return durable;
        }
    }

    let mut durable = base.clone();
    durable.height = 0;
    durable.set_latest_timestamp_ms(0);
    durable
}

fn verify_canonical_collapse_backend(collapse: &CanonicalCollapseObject) -> Result<()> {
    let proof = &collapse.continuity_recursive_proof;
    match proof.proof_system {
        CanonicalCollapseContinuityProofSystem::HashPcdV1 => Ok(()),
        CanonicalCollapseContinuityProofSystem::SuccinctSp1V1 => {
            let public_inputs = canonical_collapse_continuity_public_inputs(
                &proof.commitment,
                proof.previous_canonical_collapse_commitment_hash,
                proof.payload_hash,
                proof.previous_recursive_proof_hash,
            );
            SuccinctDriver::default()
                .verify_canonical_collapse_continuity(
                    proof.proof_system,
                    &proof.proof_bytes,
                    &public_inputs,
                )
                .map_err(|error| {
                    anyhow!(
                        "canonical collapse continuity backend verification failed for height {}: {}",
                        collapse.height,
                        error
                    )
                })
        }
    }
}

async fn verify_persisted_aft_canonical_collapse_chain(
    workload_client: &dyn WorkloadClientApi,
    collapse: &CanonicalCollapseObject,
) -> Result<()> {
    let mut chain = Vec::new();
    let mut current = collapse.clone();
    loop {
        chain.push(current.clone());
        if current.height <= 1 {
            break;
        }
        current = load_persisted_aft_canonical_collapse_object(workload_client, current.height - 1)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "missing persisted canonical collapse object for height {}",
                    current.height - 1
                )
            })?;
    }
    chain.reverse();
    let mut previous: Option<&CanonicalCollapseObject> = None;
    for current in &chain {
        verify_canonical_collapse_continuity(current, previous).map_err(|error| {
            anyhow!(
                "persisted canonical collapse continuity verification failed for height {}: {}",
                current.height,
                error
            )
        })?;
        verify_canonical_collapse_backend(current)?;
        previous = Some(current);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ioi_api::app::ChainStatus;
    use ioi_api::chain::QueryStateResponse;
    use ioi_types::app::{
        canonical_collapse_commitment, canonical_collapse_commitment_hash_from_object,
        canonical_collapse_continuity_public_inputs, canonical_collapse_extension_certificate,
        canonical_collapse_recursive_proof_hash, canonical_collapse_succinct_mock_proof_bytes,
        AccountId, CanonicalCollapseContinuityProofSystem, CanonicalCollapseExtensionCertificate,
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
}
