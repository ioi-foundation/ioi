// Path: crates/chain/src/app/mod.rs

/// The private implementation for the `SovereignChain` trait.

use crate::upgrade_manager::ModuleUpgradeManager;
use async_trait::async_trait;
use depin_sdk_core::app::{
    AppChain, ApplicationTransaction, Block, BlockHeader, ChainError, ChainStatus,
    ProtocolTransaction, SystemPayload, SystemTransaction, UTXOTransaction,
};
use depin_sdk_core::chain::SovereignChain;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::services::UpgradableService;
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
// --- FIX: Import the TransactionExecutor trait ---
use depin_sdk_core::validator::TransactionExecutor;
// --- End Fix ---
use depin_sdk_core::validator::WorkloadContainer;
use libp2p::identity::PublicKey as Libp2pPublicKey;
use libp2p::PeerId;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const STATUS_KEY: &[u8] = b"chain::status";
pub(crate) const VALIDATOR_SET_KEY: &[u8] = b"system::validators";
pub(crate) const AUTHORITY_SET_KEY: &[u8] = b"system::authorities";
pub(crate) const GOVERNANCE_KEY: &[u8] = b"system::governance_key";

#[derive(Debug)]
pub struct Chain<CS, TM: TransactionModel> {
    app_chain: AppChain<CS, TM>,
    #[allow(dead_code)]
    service_manager: ModuleUpgradeManager,
}

impl<CS, TM> Chain<CS, TM>
where
    CS: CommitmentScheme,
    TM: TransactionModel<CommitmentScheme = CS>,
{
    pub fn new(
        commitment_scheme: CS,
        transaction_model: TM,
        chain_id: &str,
        initial_services: Vec<Arc<dyn UpgradableService>>,
    ) -> Self {
        let status = ChainStatus {
            height: 0,
            latest_timestamp: 0,
            total_transactions: 0,
            is_running: false,
        };
        let mut service_manager = ModuleUpgradeManager::new();
        for service in initial_services {
            service_manager.register_service(service);
        }
        let app_chain = AppChain {
            commitment_scheme,
            transaction_model,
            chain_id: chain_id.to_string(),
            status,
            recent_blocks: Vec::new(),
            max_recent_blocks: 100,
        };
        Self {
            app_chain,
            service_manager,
        }
    }

    pub async fn load_or_initialize_status<ST>(
        &mut self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        let state_tree = workload.state_tree();
        let mut state = state_tree.lock().await;
        match state.get(STATUS_KEY) {
            Ok(Some(status_bytes)) => {
                let status: ChainStatus = serde_json::from_slice(&status_bytes)
                    .map_err(|e| ChainError::Transaction(format!("Failed to deserialize status: {}", e)))?;
                log::info!("Loaded chain status: height {}", status.height);
                self.app_chain.status = status;
            }
            Ok(None) => {
                log::info!("No existing chain status found. Initializing and saving genesis status.");
                let status_bytes = serde_json::to_vec(&self.app_chain.status).unwrap();
                state
                    .insert(STATUS_KEY, &status_bytes)
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;
            }
            Err(e) => return Err(ChainError::Transaction(e.to_string())),
        }
        Ok(())
    }

    async fn process_system_transaction<ST>(
        &mut self,
        tx: &SystemTransaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;

        let governance_pk_bytes = state.get(GOVERNANCE_KEY)?.ok_or_else(|| {
            ChainError::Transaction("Governance key not found in state".to_string())
        })?;

        let ed25519_pk =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(&governance_pk_bytes).map_err(
                |e| {
                    ChainError::Transaction(format!(
                        "Invalid Ed25519 governance public key in state: {}",
                        e
                    ))
                },
            )?;
        let libp2p_pk = Libp2pPublicKey::from(ed25519_pk);

        let payload_bytes = serde_json::to_vec(&tx.payload)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize payload: {}", e)))?;

        let is_valid_sig = libp2p_pk.verify(&payload_bytes, &tx.signature);

        if !is_valid_sig {
            return Err(ChainError::Transaction(
                "Invalid governance signature".to_string(),
            ));
        }

        match &tx.payload {
            SystemPayload::UpdateAuthorities { new_authorities } => {
                if new_authorities.is_empty() {
                    return Err(ChainError::Transaction(
                        "Authority set cannot be empty".to_string(),
                    ));
                }
                for peer_id_bytes in new_authorities {
                    if PeerId::from_bytes(peer_id_bytes).is_err() {
                        return Err(ChainError::Transaction(
                            "Invalid PeerId in new authority set".to_string(),
                        ));
                    }
                }

                let serialized_authorities = serde_json::to_vec(new_authorities).unwrap();
                state.insert(AUTHORITY_SET_KEY, &serialized_authorities)?;
                // --- FIX: Also update the validator set to prevent inconsistency. ---
                // This ensures that even if other parts of the system read the
                // validator_set key, they will get the correct, up-to-date data
                // immediately after this transaction is processed.
                state.insert(VALIDATOR_SET_KEY, &serialized_authorities)?;
                // --- END FIX ---
                log::info!(
                    "Successfully updated authority set to {} authorities via governance.",
                    new_authorities.len()
                );
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<CS, TM, ST> SovereignChain<CS, TM, ST> for Chain<CS, TM>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = UTXOTransaction>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static + Debug,
{
    fn status(&self) -> &ChainStatus {
        &self.app_chain.status
    }

    fn transaction_model(&self) -> &TM {
        &self.app_chain.transaction_model
    }

    async fn process_transaction(
        &mut self,
        tx: &ProtocolTransaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError> {
        match tx {
            ProtocolTransaction::Application(app_tx) => match app_tx {
                ApplicationTransaction::UTXO(utxo_tx) => {
                    workload
                        .execute_transaction(utxo_tx, &self.app_chain.transaction_model)
                        .await
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                }
            },
            ProtocolTransaction::System(sys_tx) => {
                self.process_system_transaction(sys_tx, workload).await?;
            }
        }
        self.app_chain.status.total_transactions += 1;
        Ok(())
    }

    async fn process_block(
        &mut self,
        mut block: Block<ProtocolTransaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Block<ProtocolTransaction>, ChainError> {
        if block.header.height != self.app_chain.status.height + 1 {
            return Err(ChainError::Block(format!(
                "Invalid block height. Expected {}, got {}",
                self.app_chain.status.height + 1,
                block.header.height
            )));
        }
        let expected_prev_hash = self
            .app_chain
            .recent_blocks
            .last()
            .map_or(vec![0; 32], |b| b.header.state_root.clone());
        if block.header.prev_hash != expected_prev_hash {
            return Err(ChainError::Block(format!(
                "Invalid prev_hash for block {}. Expected {}, got {}",
                block.header.height,
                hex::encode(&expected_prev_hash),
                hex::encode(&block.header.prev_hash)
            )));
        }
        for tx in &block.transactions {
            self.process_transaction(tx, workload).await?;
        }
        self.app_chain.status.height = block.header.height;
        self.app_chain.status.latest_timestamp = block.header.timestamp;

        let status_bytes = serde_json::to_vec(&self.app_chain.status)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize status: {}", e)))?;
        let validator_set_bytes = serde_json::to_vec(&block.header.validator_set).map_err(|e| {
            ChainError::Transaction(format!("Failed to serialize validator set: {}", e))
        })?;

        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;
        state.insert(STATUS_KEY, &status_bytes)?;
        state.insert(VALIDATOR_SET_KEY, &validator_set_bytes)?;

        let state_root = state.root_commitment();
        drop(state);

        block.header.state_root = state_root.as_ref().to_vec();
        self.app_chain.recent_blocks.push(block.clone());
        if self.app_chain.recent_blocks.len() > self.app_chain.max_recent_blocks {
            self.app_chain.recent_blocks.remove(0);
        }
        Ok(block)
    }

    fn create_block(
        &self,
        transactions: Vec<ProtocolTransaction>,
        _workload: &WorkloadContainer<ST>,
        current_validator_set: &Vec<Vec<u8>>,
        _known_peers_bytes: &Vec<Vec<u8>>,
    ) -> Block<ProtocolTransaction> {
        let prev_hash = self
            .app_chain
            .recent_blocks
            .last()
            .map_or(vec![0; 32], |b| b.header.state_root.clone());

        // The validator set for the new block should be exactly the authority set
        // passed in, ensuring it reflects the current consensus state without
        // incorrectly adding peers. We still parse, sort, and re-serialize to
        // ensure canonical representation.
        let mut peers: Vec<PeerId> = current_validator_set
            .iter()
            .filter_map(|bytes| PeerId::from_bytes(bytes).ok())
            .collect();
        peers.sort(); // Ensure deterministic ordering.
        let validator_set: Vec<Vec<u8>> =
            peers.iter().map(|p| p.to_bytes()).collect();

        let next_height = self.app_chain.status.height + 1;
        let header = BlockHeader {
            height: next_height,
            prev_hash: prev_hash.clone(),
            state_root: prev_hash,
            transactions_root: vec![0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            validator_set,
        };
        Block {
            header,
            transactions,
        }
    }

    fn get_block(&self, height: u64) -> Option<&Block<ProtocolTransaction>> {
        self.app_chain
            .recent_blocks
            .iter()
            .find(|b| b.header.height == height)
    }

    fn get_blocks_since(&self, height: u64) -> Vec<Block<ProtocolTransaction>> {
        self.app_chain
            .recent_blocks
            .iter()
            .filter(|b| b.header.height > height)
            .cloned()
            .collect()
    }

    async fn get_validator_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(VALIDATOR_SET_KEY) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_err(|e| {
                ChainError::Transaction(format!("Failed to deserialize validator set: {}", e))
            }),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_authority_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(AUTHORITY_SET_KEY) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_err(|e| {
                ChainError::Transaction(format!("Failed to deserialize authority set: {}", e))
            }),
            Ok(None) => Err(ChainError::State(
                depin_sdk_core::error::StateError::KeyNotFound(
                    "system::authorities not found in state. Check genesis file.".to_string(),
                ),
            )),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depin_sdk_core::config::WorkloadConfig;
    use depin_sdk_core::state::StateTree;
    use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
    use depin_sdk_state_trees::hashmap::HashMapStateTree;
    use depin_sdk_transaction_models::utxo::UTXOModel;
    use libp2p::identity;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_process_system_transaction_update_authorities() {
        // Setup
        let scheme = HashCommitmentScheme::new();
        let state_tree = HashMapStateTree::new(scheme.clone());
        let workload = Arc::new(WorkloadContainer::new(
            WorkloadConfig {
                enabled_vms: vec![],
            },
            state_tree,
        ));
        let mut chain = Chain::new(scheme.clone(), UTXOModel::new(scheme), "test-chain", vec![]);

        let gov_keypair = identity::Keypair::generate_ed25519();
        let gov_pk_bytes = gov_keypair
            .public()
            .try_into_ed25519()
            .unwrap()
            .to_bytes()
            .to_vec();

        workload
            .state_tree()
            .lock()
            .await
            .insert(GOVERNANCE_KEY, &gov_pk_bytes)
            .unwrap();

        // Create transaction
        let new_authorities = vec![PeerId::random().to_bytes()];
        let payload = SystemPayload::UpdateAuthorities {
            new_authorities: new_authorities.clone(),
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = gov_keypair.sign(&payload_bytes).unwrap();
        let sys_tx = SystemTransaction {
            payload,
            signature,
        };
        let protocol_tx = ProtocolTransaction::System(sys_tx);

        // Test
        let result = chain.process_transaction(&protocol_tx, &workload).await;
        assert!(result.is_ok());

        // Verify
        let stored_bytes = workload
            .state_tree()
            .lock()
            .await
            .get(AUTHORITY_SET_KEY)
            .unwrap()
            .unwrap();
        let stored_authorities: Vec<Vec<u8>> = serde_json::from_slice(&stored_bytes).unwrap();
        assert_eq!(stored_authorities, new_authorities);
    }

    #[tokio::test]
    async fn test_process_system_tx_invalid_signature() {
        // Setup
        let scheme = HashCommitmentScheme::new();
        let state_tree = HashMapStateTree::new(scheme.clone());
        let workload = Arc::new(WorkloadContainer::new(
            WorkloadConfig {
                enabled_vms: vec![],
            },
            state_tree,
        ));
        let mut chain = Chain::new(scheme.clone(), UTXOModel::new(scheme), "test-chain", vec![]);
        let gov_keypair = identity::Keypair::generate_ed25519();
        let gov_pk_bytes = gov_keypair
            .public()
            .try_into_ed25519()
            .unwrap()
            .to_bytes()
            .to_vec();

        workload
            .state_tree()
            .lock()
            .await
            .insert(GOVERNANCE_KEY, &gov_pk_bytes)
            .unwrap();

        // Create transaction with invalid signature
        let new_authorities = vec![PeerId::random().to_bytes()];
        let payload = SystemPayload::UpdateAuthorities { new_authorities };
        let sys_tx = SystemTransaction {
            payload,
            signature: b"invalid-signature".to_vec(),
        };
        let protocol_tx = ProtocolTransaction::System(sys_tx);

        let result = chain.process_transaction(&protocol_tx, &workload).await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(ChainError::Transaction(msg)) if msg == "Invalid governance signature")
        );
    }
}