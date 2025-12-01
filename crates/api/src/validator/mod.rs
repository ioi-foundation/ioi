// Path: crates/api/src/validator/mod.rs
use crate::{
    services::access::ServiceDirectory,
    state::{RetentionManager, StateManager, StateVersionPins, VmStateAccessor}, // [UPDATED]
    storage::{NodeStore, PruneStats},
    vm::{ExecutionContext, ExecutionOutput, VirtualMachine, VmStateOverlay},
};
use async_trait::async_trait;
use dcrypt::algorithms::{
    hash::{sha2::Sha256 as DcryptSha256, HashFunction},
    ByteSerializable,
};
use ioi_types::app::{Membership, StateEntry};
use ioi_types::codec;
use ioi_types::config::WorkloadConfig;
use ioi_types::error::ValidatorError;
use lru::LruCache;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

pub mod container;
pub mod types;

pub use container::{Container, GuardianContainer};
pub use types::ValidatorModel;

/// The key for the state proof cache: a tuple of (state_root, key).
pub type ProofCacheKey = (Vec<u8>, Vec<u8>);
/// The value for the state proof cache: a tuple of (membership_outcome, proof).
pub type ProofCacheValue<P> = (Membership, P);
/// The underlying LRU cache store for state proofs.
pub type ProofCacheStore<P> = LruCache<ProofCacheKey, ProofCacheValue<P>>;
/// A thread-safe handle to the state proof cache.
pub type ProofCache<P> = Arc<Mutex<ProofCacheStore<P>>>;

/// A container responsible for executing transactions, smart contracts, and managing state.
pub struct WorkloadContainer<ST: StateManager> {
    config: WorkloadConfig,
    state_tree: Arc<RwLock<ST>>,
    vm: Box<dyn VirtualMachine>,
    services: ServiceDirectory,
    /// A concurrent, in-memory cache for recently generated state proofs.
    /// The key is a tuple of (state_root, key), and the value is the proof.
    /// This is made public to allow the IPC server to access it.
    pub proof_cache: ProofCache<ST::Proof>,
    /// The retention manager for handling state pruning and historical access.
    pub retention_manager: Arc<RetentionManager>, // [CHANGED]
    /// The durable, epoch-sharded storage backend for state tree nodes.
    pub store: Arc<dyn NodeStore>,
}

impl<ST: StateManager + Debug> Debug for WorkloadContainer<ST> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadContainer")
            .field("config", &self.config)
            .field("state_tree", &self.state_tree)
            .field("vm", &"Box<dyn VirtualMachine>")
            .field("services", &"ServiceDirectory")
            .field("proof_cache", &"LruCache")
            .field("retention_manager", &self.retention_manager) // [CHANGED]
            .field("store", &"Arc<dyn NodeStore>")
            .finish()
    }
}

/// A private wrapper to provide a dyn-safe, `Arc`-able view of a generic `StateManager`
/// for the VM. Its lifetime is managed by `Arc`, ensuring it lives as long as the VM
/// execution context that holds a reference to it.
struct StateAccessorWrapper<ST: StateManager> {
    state_tree: Arc<RwLock<ST>>,
}

#[async_trait]
impl<ST: StateManager + Send + Sync> VmStateAccessor for StateAccessorWrapper<ST> {
    /// Delegates the `get` call to the underlying state manager, handling the lock.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ioi_types::error::StateError> {
        self.state_tree.read().await.get(key)
    }

    /// Delegates the `insert` call to the underlying state manager, handling the lock.
    async fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), ioi_types::error::StateError> {
        self.state_tree.write().await.insert(key, value)
    }

    /// Delegates the `delete` call to the underlying state manager, handling the lock.
    async fn delete(&self, key: &[u8]) -> Result<(), ioi_types::error::StateError> {
        self.state_tree.write().await.delete(key)
    }

    /// Scans keys with the given prefix and returns all matching key-value pairs.
    async fn prefix_scan(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ioi_types::error::StateError> {
        let state = self.state_tree.read().await;
        let iter = state.prefix_scan(prefix)?;
        // Collect the iterator into a Vec to satisfy the async trait signature
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }
}

impl<ST> WorkloadContainer<ST>
where
    ST: StateManager + Send + Sync + 'static,
{
    /// Creates a new `WorkloadContainer`.
    pub fn new(
        config: WorkloadConfig,
        state_tree: ST,
        vm: Box<dyn VirtualMachine>,
        services: ServiceDirectory,
        store: Arc<dyn NodeStore>,
    ) -> Result<Self, ValidatorError> {
        let nz_one = NonZeroUsize::new(1).ok_or(ValidatorError::Config(
            "NonZeroUsize::new failed for LRU cache".into(),
        ))?;

        // [CHANGED] Initialize RetentionManager
        let retention_manager = Arc::new(RetentionManager::new());

        Ok(Self {
            config,
            state_tree: Arc::new(RwLock::new(state_tree)),
            vm,
            services,
            proof_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(1024).unwrap_or(nz_one),
            ))),
            retention_manager, // [CHANGED]
            store,
        })
    }

    /// Access the underlying sparse pins system (e.g., for creating PinGuards).
    // [NEW] Helper to keep API compatibility
    pub fn pins(&self) -> &Arc<StateVersionPins> {
        self.retention_manager.pins()
    }

    /// Returns a reference to the workload's configuration.
    pub fn config(&self) -> &WorkloadConfig {
        &self.config
    }

    /// Returns a thread-safe handle to the state tree.
    pub fn state_tree(&self) -> Arc<RwLock<ST>> {
        self.state_tree.clone()
    }

    /// Returns a read-only directory of available services.
    pub fn services(&self) -> &ServiceDirectory {
        &self.services
    }

    /// Prepares the deployment of a new smart contract.
    /// Returns the deterministic address and a map of state changes to be applied.
    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        sender: Vec<u8>,
    ) -> Result<(Vec<u8>, HashMap<Vec<u8>, Vec<u8>>), ValidatorError> {
        let mut state_changes = HashMap::new();
        let data_to_hash = [sender, code.clone()].concat();
        let address = DcryptSha256::digest(&data_to_hash)
            .map_err(|e| ValidatorError::Other(e.to_string()))?
            .to_bytes()
            .to_vec();

        let code_key = [b"contract_code::".as_ref(), &address].concat();
        state_changes.insert(code_key, code);

        log::info!(
            "Prepared deployment for contract at address: {}",
            hex::encode(&address)
        );
        Ok((address, state_changes))
    }

    /// A specialized version of `call_contract` that executes pre-loaded contract code.
    /// This is used by the transaction model's `apply_payload` to avoid a state-tree deadlock
    /// when simulating transactions within a read-locked state overlay. This method does NOT
    /// access the `state_tree` directly.
    pub async fn execute_loaded_contract(
        &self,
        code: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<(ExecutionOutput, (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>)), ValidatorError> {
        let parent_accessor = Arc::new(StateAccessorWrapper {
            state_tree: self.state_tree.clone(),
        });
        let overlay = VmStateOverlay::new(parent_accessor);
        let overlay_arc = Arc::new(overlay);

        let output = self
            .vm
            .execute(&code, "call", &input_data, overlay_arc.as_ref(), context)
            .await?;

        let state_delta = overlay_arc.snapshot_writes();
        log::info!(
            "Contract call successful. Gas used: {}. Return data size: {}. State changes (inserts/deletes): {}/{}",
            output.gas_used,
            output.return_data.len(),
            state_delta.0.len(),
            state_delta.1.len(),
        );

        Ok((output, state_delta))
    }

    /// Executes a contract call and returns the execution output and state delta.
    /// This method fetches the contract code from the canonical state.
    pub async fn call_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        mut context: ExecutionContext,
    ) -> Result<(ExecutionOutput, (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>)), ValidatorError> {
        let code = {
            let state = self.state_tree.read().await;
            let code_key = [b"contract_code::".as_ref(), &address].concat();
            let stored_bytes = state
                .get(&code_key)?
                .ok_or_else(|| ValidatorError::Other("Contract not found".to_string()))?;
            let stored_entry: StateEntry =
                codec::from_bytes_canonical(&stored_bytes).map_err(|e| {
                    ValidatorError::State(ioi_types::error::StateError::InvalidValue(e.to_string()))
                })?;
            stored_entry.value
        };

        context.contract_address = address.clone();

        self.execute_loaded_contract(code, input_data, context)
            .await
    }

    /// Queries an existing smart contract without persisting state changes.
    pub async fn query_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        mut context: ExecutionContext,
    ) -> Result<ExecutionOutput, ValidatorError> {
        let code = {
            let state = self.state_tree.read().await;
            let code_key = [b"contract_code::".as_ref(), &address].concat();
            let stored_bytes = state
                .get(&code_key)?
                .ok_or_else(|| ValidatorError::Other("Contract not found".to_string()))?;
            let stored_entry: StateEntry =
                codec::from_bytes_canonical(&stored_bytes).map_err(|e| {
                    ValidatorError::State(ioi_types::error::StateError::InvalidValue(e.to_string()))
                })?;
            stored_entry.value
        };

        context.contract_address = address.clone();

        let parent_accessor = Arc::new(StateAccessorWrapper {
            state_tree: self.state_tree.clone(),
        });
        let overlay = VmStateOverlay::new(parent_accessor);

        let output = self
            .vm
            .execute(&code, "call", &input_data, &overlay, context)
            .await?;

        Ok(output)
    }

    /// Runs a single pass of the Garbage Collector.
    ///
    /// This method delegates the calculation of the pruning plan to the `RetentionManager`,
    /// which aggregates configuration, sparse pins, and long-running retention clients.
    ///
    /// # Arguments
    ///
    /// * `current_height` - The current block height of the chain.
    ///
    /// # Returns
    ///
    /// * `PruneStats` - Statistics about what was pruned (heights and nodes).
    pub async fn run_gc_pass(&self, current_height: u64) -> Result<PruneStats, ValidatorError> {
        const BATCH_LIMIT: usize = 1_000;
        const MAX_BATCHES_PER_TICK: usize = 10;

        let gc_config = &self.config;

        // [CHANGED] Delegate plan calculation to the RetentionManager
        let plan = self.retention_manager.calculate_prune_plan(
            current_height,
            gc_config.keep_recent_heights,
            gc_config.min_finality_depth,
        );

        if plan.cutoff_height == 0 {
            return Ok(PruneStats::default());
        }

        // 4. Prune In-Memory State (StateManager)
        // We try to acquire a write lock. If we can't, we skip this part to avoid stalling the node.
        if let Ok(mut state_tree) = self.state_tree.try_write() {
            if let Err(e) = state_tree.prune_batch(&plan, BATCH_LIMIT * MAX_BATCHES_PER_TICK) {
                log::error!("[GC] Failed to prune in-memory state versions: {}", e);
            }
        } else {
            log::warn!("[GC] Could not acquire lock for in-memory prune, skipping this cycle.");
        }

        // 5. Drop Sealed Epochs (NodeStore)
        // [FIX] Disabled: drop_sealed_epoch is unsafe because nodes created in old epochs
        // are shared/referenced by newer versions. Deleting them breaks historical access
        // for pinned heights.
        /*
        let cutoff_epoch = self.store.epoch_of(plan.cutoff_height);

        // The cutoff_epoch will naturally be 0 if cutoff_height was forced to 0 above,
        // effectively disabling this loop as well.
        for epoch_id in 0..cutoff_epoch {
            if self.store.is_sealed(epoch_id).unwrap_or(false) {
                if let Err(err) = self.store.drop_sealed_epoch(epoch_id) {
                    log::error!("[GC] Failed to drop sealed epoch {}: {}", epoch_id, err);
                } else {
                    log::info!("[GC] Dropped sealed epoch {}", epoch_id);
                }
            }
        }
        */

        // 6. Prune Heights from NodeStore
        let mut total_stats = PruneStats::default();
        for _ in 0..MAX_BATCHES_PER_TICK {
            let excluded_vec: Vec<u64> = plan.excluded_heights.iter().cloned().collect();
            match self
                .store
                .prune_batch(plan.cutoff_height, &excluded_vec, BATCH_LIMIT)
            {
                Ok(stats) => {
                    total_stats.heights_pruned += stats.heights_pruned;
                    total_stats.nodes_deleted += stats.nodes_deleted;
                    if stats.heights_pruned < BATCH_LIMIT {
                        break;
                    }
                }
                Err(e) => {
                    log::error!("[GC] Store prune_batch failed: {}", e);
                    return Err(ValidatorError::Other(e.to_string()));
                }
            }
            tokio::task::yield_now().await;
        }

        if total_stats.heights_pruned > 0 {
            log::debug!(
                "[GC] Pruned {} heights, deleted {} nodes (cutoff {})",
                total_stats.heights_pruned,
                total_stats.nodes_deleted,
                plan.cutoff_height,
            );
        }

        // Clear the proof cache after GC to ensure we don't serve stale proofs
        // for data that has been pruned from the backing store.
        self.proof_cache.lock().await.clear();

        Ok(total_stats)
    }
}

#[async_trait]
impl<ST> Container for WorkloadContainer<ST>
where
    ST: StateManager + Send + Sync + 'static,
{
    async fn start(&self, _listen_addr: &str) -> Result<(), ValidatorError> {
        log::info!("WorkloadContainer started.");
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("WorkloadContainer stopped.");
        Ok(())
    }

    fn is_running(&self) -> bool {
        true
    }

    fn id(&self) -> &'static str {
        "workload_container"
    }
}
