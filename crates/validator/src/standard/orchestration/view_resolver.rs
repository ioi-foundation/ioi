// Path: crates/validator/src/standard/orchestration/view_resolver.rs
use async_trait::async_trait;
use lru::LruCache;
use std::{any::Any, sync::Arc};

use ioi_api::chain::{AnchoredStateView, StateRef, ViewResolver, WorkloadClientApi};
use ioi_api::state::Verifier;
use ioi_client::WorkloadClient;
use ioi_types::{
    app::{to_root_hash, StateAnchor},
    error::ChainError,
};
use tokio::sync::Mutex;

use super::remote_state_view::DefaultAnchoredStateView;

pub struct DefaultViewResolver<V: Verifier> {
    // Store client as both concrete type and trait object
    client: Arc<WorkloadClient>,
    client_api: Arc<dyn WorkloadClientApi>,
    verifier: V,
    proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
}

impl<V: Verifier> DefaultViewResolver<V> {
    // Helper getters used by orchestration/gossip
    pub fn workload_client(&self) -> &Arc<WorkloadClient> {
        &self.client
    }
    pub fn verifier(&self) -> &V {
        &self.verifier
    }
    pub fn proof_cache(&self) -> &Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>> {
        &self.proof_cache
    }
    pub fn new(
        client: Arc<WorkloadClient>,
        verifier: V,
        proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
    ) -> Self {
        // Upcast the concrete client to the trait object immediately
        let client_api = client.clone() as Arc<dyn WorkloadClientApi>;
        Self {
            client,
            client_api,
            verifier,
            proof_cache,
        }
    }
}

#[async_trait]
impl<V> ViewResolver for DefaultViewResolver<V>
where
    V: Verifier + Send + Sync + 'static + Clone,
{
    type Verifier = V;

    async fn resolve_anchored(
        &self,
        r: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError> {
        // Use to_root_hash to derive a fixed-size anchor from the raw root.
        let anchor_hash = to_root_hash(&r.state_root).map_err(ChainError::State)?;
        let anchor = StateAnchor(anchor_hash);
        let root = ioi_types::app::StateRoot(r.state_root.clone());
        let view = DefaultAnchoredStateView::new(
            anchor,
            root,
            r.height,
            self.client_api.clone(), // Pass the trait object, not the concrete type
            self.verifier.clone(),
            self.proof_cache.clone(),
        );
        Ok(Arc::new(view))
    }

    async fn resolve_live(&self) -> Result<Arc<dyn ioi_api::chain::LiveStateView>, ChainError> {
        // Not used yet; you can add a lightweight head-following view later.
        Err(ChainError::Transaction(
            "LiveStateView not implemented".into(),
        ))
    }

    async fn genesis_root(&self) -> Result<Vec<u8>, ChainError> {
        // Use the dedicated, robust RPC call via the trait interface
        let ready = self
            .client_api
            .get_genesis_status()
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))?;

        if ready {
            let status = self
                .client
                .get_genesis_status()
                .await
                .map_err(|e| ChainError::Transaction(e.to_string()))?;
            if status.ready {
                Ok(status.root)
            } else {
                Err(ChainError::Transaction(
                    "Genesis state is not ready yet.".into(),
                ))
            }
        } else {
            Err(ChainError::Transaction(
                "Genesis state is not ready yet.".into(),
            ))
        }
    }

    fn workload_client(&self) -> &Arc<dyn WorkloadClientApi> {
        &self.client_api
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
