// Path: crates/execution/src/app/state_machine.rs

use super::{end_block, ExecutionMachine};
use async_trait::async_trait;
use ibc_primitives::Timestamp;
use ioi_api::app::{Block, BlockHeader, ChainStatus, ChainTransaction};
use ioi_api::chain::{ChainStateMachine, PreparedBlock};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::{PinGuard, ProofProvider, StateManager, StateOverlay};
use ioi_api::transaction::context::TxContext;
// REMOVED: use ioi_api::validator::WorkloadContainer;
use ioi_tx::unified::UnifiedProof;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    account_id_from_key_material, read_validator_sets, to_root_hash, AccountId, Membership,
    SignatureSuite, StateRoot,
};
use ioi_types::codec;
use ioi_types::config::ConsensusType;
use ioi_types::error::{BlockError, ChainError, StateError};
use ioi_types::keys::{STATUS_KEY, UPGRADE_ACTIVE_SERVICE_PREFIX, VALIDATOR_SET_KEY};
use ioi_types::service_configs::ActiveServiceMeta;
use libp2p::identity::Keypair;
use parity_scale_codec::Decode;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

#[async_trait]
impl<CS, ST> ChainStateMachine<CS, UnifiedTransactionModel<CS>, ST> for ExecutionMachine<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static
        + Clone,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: AsRef<[u8]>
        + Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Decode
        + Debug,
    // UPDATED: Added Debug + Send + Sync to match ExecutionMachine impl bounds
    <CS as CommitmentScheme>::Commitment: From<Vec<u8>> + Debug + Send + Sync,
{
    fn status(&self) -> &ChainStatus {
        &self.state.status
    }

    fn status_mut(&mut self) -> &mut ChainStatus {
        &mut self.state.status
    }

    fn transaction_model(&self) -> &UnifiedTransactionModel<CS> {
        &self.state.transaction_model
    }

    async fn prepare_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> Result<PreparedBlock, ChainError> {
        let workload = &self.workload_container;
        let expected_height = self.state.status.height + 1;
        if block.header.height != expected_height {
            return Err(ChainError::Block(BlockError::InvalidHeight {
                expected: expected_height,
                got: block.header.height,
            }));
        }

        let mut proofs_out = Vec::with_capacity(block.transactions.len());
        let mut block_gas_used = 0u64;
        let state_changes = {
            // [CHANGED] Use the pins() method exposed by WorkloadContainer
            let _pin_guard = PinGuard::new(workload.pins().clone(), self.state.status.height);
            let snapshot_state = {
                let state_tree_arc = workload.state_tree();
                let backend_guard = state_tree_arc.read().await;
                backend_guard.clone()
            };
            let mut overlay = StateOverlay::new(&snapshot_state);

            for tx in &block.transactions {
                match self
                    .process_transaction(
                        tx,
                        &mut overlay,
                        block.header.height,
                        block.header.timestamp,
                        &mut proofs_out,
                    )
                    .await
                {
                    Ok(gas) => {
                        block_gas_used += gas;
                    }
                    Err(e) => {
                        tracing::error!(target: "block", height = block.header.height, error = %e, "process_transaction failed; rejecting block proposal");
                        return Err(e);
                    }
                }
            }

            overlay.into_ordered_batch()
        };

        let transactions_root = ioi_types::codec::to_bytes_canonical(&block.transactions)
            .map_err(ChainError::Transaction)?;
        let vs_bytes = self.get_validator_set_for(block.header.height).await?;
        let validator_set_hash = ioi_crypto::algorithms::hash::sha256(vs_bytes.concat())
            .map_err(|e| ChainError::Transaction(e.to_string()))?;

        Ok(PreparedBlock {
            block,
            state_changes: Arc::new(state_changes),
            parent_state_root: self.state.last_state_root.clone(),
            transactions_root,
            validator_set_hash,
            tx_proofs: proofs_out,
            gas_used: block_gas_used,
        })
    }

    async fn commit_block(
        &mut self,
        prepared: PreparedBlock,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        let workload = &self.workload_container;
        let mut block = prepared.block;
        let state_changes = prepared.state_changes;
        let (inserts, deletes) = state_changes.as_ref();

        if block.header.height != self.state.status.height + 1 {
            return Err(ChainError::Transaction(
                "Stale preparation: Chain height advanced since block was prepared".into(),
            ));
        }
        if prepared.parent_state_root != self.state.last_state_root {
            return Err(ChainError::Transaction(
                "Stale preparation: Parent state root has changed since block was prepared".into(),
            ));
        }

        // --- VERIFY PROOFS ---
        let backend = {
            let tree_arc = workload.state_tree();
            let guard = tree_arc.read().await;
            guard.clone()
        };
        let commit = backend
            .commitment_from_bytes(&prepared.parent_state_root)
            .map_err(ChainError::State)?;

        for (i, _tx) in block.transactions.iter().enumerate() {
            let proof_bytes = prepared.tx_proofs.get(i).ok_or_else(|| {
                ChainError::Transaction("Missing proof for transaction".to_string())
            })?;

            let proof: UnifiedProof<<CS as CommitmentScheme>::Proof> =
                codec::from_bytes_canonical(proof_bytes).map_err(ChainError::Transaction)?;

            match proof {
                UnifiedProof::UTXO(p) => {
                    for ip in p.input_proofs {
                        backend
                            .verify_proof(
                                &commit,
                                &ip.inclusion_proof,
                                &ip.utxo_key,
                                &ip.utxo_value,
                            )
                            .map_err(ChainError::State)?;
                    }
                }
                _ => { /* Verification for other proof types would go here */ }
            }
        }

        drop(backend); // Release read lock before acquiring write lock

        let final_state_root_bytes = {
            let state_tree_arc = workload.state_tree();
            let mut state = state_tree_arc.write().await;

            state.begin_block_writes(block.header.height);
            state.batch_apply(inserts, deletes)?;

            let upgrade_count = end_block::handle_service_upgrades(
                &mut self.service_manager,
                block.header.height,
                &mut *state,
            )
            .await?;

            if upgrade_count > 0 {
                self.services =
                    ServiceDirectory::new(self.service_manager.all_services_as_trait_objects());
                // MODIFIED: Refresh the metadata cache after upgrades.
                self.service_meta_cache.clear();
                let service_iter = state.prefix_scan(UPGRADE_ACTIVE_SERVICE_PREFIX)?;
                for item in service_iter {
                    let (_key, meta_bytes) = item?;
                    if let Ok(meta) = codec::from_bytes_canonical::<ActiveServiceMeta>(&meta_bytes)
                    {
                        self.service_meta_cache
                            .insert(meta.id.clone(), Arc::new(meta));
                    }
                }
            }

            let end_block_ctx = TxContext {
                block_height: block.header.height,
                block_timestamp: {
                    let ts_ns: u64 = (block.header.timestamp as u128)
                        .saturating_mul(1_000_000_000)
                        .try_into()
                        .map_err(|_| ChainError::Transaction("Timestamp overflow".to_string()))?;
                    Timestamp::from_nanoseconds(ts_ns)
                        .map_err(|e| ChainError::Transaction(format!("Invalid timestamp: {}", e)))?
                },
                chain_id: self.state.chain_id,
                signer_account_id: AccountId::default(),
                services: &self.services,
                simulation: false,
                is_internal: true,
            };

            end_block::run_on_end_block_hooks(
                &self.services,
                &mut *state,
                &end_block_ctx,
                &self.service_meta_cache,
            )
            .await?;
            end_block::handle_validator_set_promotion(&mut *state, block.header.height)?;
            end_block::handle_timing_update(&mut *state, block.header.height, prepared.gas_used)?;

            self.state.status.height = block.header.height;
            self.state.status.latest_timestamp = block.header.timestamp;
            self.state.status.total_transactions += block.transactions.len() as u64;

            let status_bytes =
                codec::to_bytes_canonical(&self.state.status).map_err(ChainError::Transaction)?;
            state.insert(STATUS_KEY, &status_bytes)?;

            state.commit_version_persist(block.header.height, &*workload.store)?;
            let final_root_bytes = state.root_commitment().as_ref().to_vec();

            {
                let final_commitment = state.commitment_from_bytes(&final_root_bytes)?;
                if cfg!(debug_assertions) && !state.version_exists_for_root(&final_commitment) {
                    return Err(ChainError::State(StateError::Validation(format!("FATAL INVARIANT VIOLATION: The committed root for height {} is not mapped to a queryable version!", block.header.height))));
                }
                if self.consensus_engine.consensus_type() == ConsensusType::ProofOfStake {
                    match state.get_with_proof_at(&final_commitment, VALIDATOR_SET_KEY) {
                        Ok((Membership::Present(_), _)) => {
                            tracing::info!(target: "pos_finality_check", event = "validator_set_provable", height = block.header.height, root = hex::encode(&final_root_bytes), "OK");
                        }
                        Ok((other, _)) => {
                            return Err(ChainError::State(StateError::Validation(format!("INVARIANT: Validator set missing at end of block {} (membership={:?}, root={})", block.header.height, other, hex::encode(&final_root_bytes)))));
                        }
                        Err(e) => {
                            return Err(ChainError::State(StateError::Validation(format!("INVARIANT: get_with_proof_at failed for validator set at end of block {}: {}", block.header.height, e))));
                        }
                    }
                }
            }
            final_root_bytes
        };

        block.header.state_root = StateRoot(final_state_root_bytes.clone());
        block.header.gas_used = prepared.gas_used;
        self.state.last_state_root = final_state_root_bytes;

        let anchor = StateRoot(block.header.state_root.0.clone())
            .to_anchor()
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        tracing::info!(target: "execution", event = "commit", height = block.header.height, state_root = hex::encode(&block.header.state_root.0), anchor = hex::encode(anchor.as_ref()));

        let block_bytes = codec::to_bytes_canonical(&block).map_err(ChainError::Transaction)?;
        workload
            .store
            .put_block(block.header.height, &block_bytes)
            .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?;

        if self.state.recent_blocks.len() >= self.state.max_recent_blocks {
            self.state.recent_blocks.remove(0);
        }
        self.state.recent_blocks.push(block.clone());

        let events = vec![];
        Ok((block, events))
    }

    fn create_block(
        &self,
        transactions: Vec<ChainTransaction>,
        current_validator_set: &[Vec<u8>],
        _known_peers_bytes: &[Vec<u8>],
        producer_keypair: &Keypair,
        expected_timestamp: u64,
        view: u64, // <--- NEW parameter
    ) -> Result<Block<ChainTransaction>, ChainError> {
        let height = self.state.status.height + 1;
        let (parent_hash_vec, parent_state_root) = self.state.recent_blocks.last().map_or_else(
            || {
                let parent_hash =
                    to_root_hash(&self.state.last_state_root).map_err(ChainError::State)?;
                Ok((
                    parent_hash.to_vec(),
                    StateRoot(self.state.last_state_root.clone()),
                ))
            },
            |b| -> Result<_, ChainError> {
                Ok((
                    b.header.hash().unwrap_or(vec![0; 32]),
                    b.header.state_root.clone(),
                ))
            },
        )?;

        let parent_hash: [u8; 32] = parent_hash_vec.try_into().map_err(|_| {
            ChainError::Block(BlockError::Hash("Parent hash was not 32 bytes".into()))
        })?;

        let producer_pubkey = producer_keypair.public().encode_protobuf();
        let suite = SignatureSuite::Ed25519;
        let producer_pubkey_hash = account_id_from_key_material(suite, &producer_pubkey)?;
        let producer_account_id = AccountId(producer_pubkey_hash);

        let timestamp = expected_timestamp;

        let mut header = BlockHeader {
            height,
            view, // <--- Set view
            parent_hash,
            parent_state_root,
            state_root: StateRoot(vec![]),
            transactions_root: vec![],
            timestamp,
            gas_used: 0,
            validator_set: current_validator_set.to_vec(),
            producer_account_id,
            producer_key_suite: suite,
            producer_pubkey_hash,
            producer_pubkey,
            signature: vec![],
        };

        let preimage = header
            .to_preimage_for_signing()
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        let signature = producer_keypair
            .sign(&preimage)
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        header.signature = signature;

        Ok(Block {
            header,
            transactions,
        })
    }

    fn get_block(&self, height: u64) -> Option<&Block<ChainTransaction>> {
        self.state
            .recent_blocks
            .iter()
            .find(|b| b.header.height == height)
    }

    fn get_blocks_since(&self, height: u64) -> Vec<Block<ChainTransaction>> {
        self.state
            .recent_blocks
            .iter()
            .filter(|b| b.header.height > height)
            .cloned()
            .collect()
    }

    async fn get_validator_set_for(&self, height: u64) -> Result<Vec<Vec<u8>>, ChainError> {
        let workload = &self.workload_container;
        let state = workload.state_tree();
        let state_guard = state.read().await;
        let bytes = state_guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or(ChainError::from(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&bytes)?;
        let effective_set = ioi_types::app::effective_set_for_height(&sets, height);
        Ok(effective_set
            .validators
            .iter()
            .map(|v| v.account_id.0.to_vec())
            .collect())
    }

    async fn get_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, ChainError> {
        let state = self.workload_container.state_tree();
        let guard = state.read().await;
        let bytes = guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or_else(|| ChainError::from(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&bytes)?;
        Ok(sets
            .current
            .validators
            .into_iter()
            .map(|v| (v.account_id, v.weight as u64))
            .collect())
    }

    async fn get_next_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, ChainError> {
        let state = self.workload_container.state_tree();
        let guard = state.read().await;
        let bytes = guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or_else(|| ChainError::from(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&bytes)?;
        let effective_set = sets.next.as_ref().unwrap_or(&sets.current);
        Ok(effective_set
            .validators
            .iter()
            .map(|v| (v.account_id, v.weight as u64))
            .collect())
    }
}
