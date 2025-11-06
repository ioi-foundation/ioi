// Path: crates/validator/src/standard/orchestration/view_resolver.rs
use async_trait::async_trait;
use lru::LruCache;
use std::{any::Any, sync::Arc};

use ioi_client::WorkloadClient;
use ioi_api::chain::{AnchoredStateView, StateRef, ViewResolver};
use ioi_api::state::Verifier;
use ioi_types::{
    app::{to_root_hash, StateAnchor},
    error::ChainError,
};
use tokio::sync::Mutex;

use super::remote_state_view::DefaultAnchoredStateView;

pub struct DefaultViewResolver<V: Verifier> {
    client: Arc<WorkloadClient>,
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
        Self {
            client,
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
            self.client.clone(),
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
        // Use the dedicated, robust RPC call.
        let status = self
            .client
            .get_genesis_status()
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        if status.ready {
            Ok(status.root)
        } else {
            // If genesis isn't ready, it's a transient error. Returning an error is better than a zero hash.
            Err(ChainError::Transaction(
                "Genesis state is not ready yet.".into(),
            ))
        }
    }

    fn workload_client(&self) -> &dyn Any {
        self.client.as_ref()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
