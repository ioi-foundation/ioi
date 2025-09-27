// Path: crates/validator/src/standard/orchestration/view_resolver.rs
use async_trait::async_trait;
use lru::LruCache;
use std::{any::Any, sync::Arc};

use depin_sdk_api::chain::{AnchoredStateView, StateRef, ViewResolver};
use depin_sdk_api::state::Verifier;
use depin_sdk_client::WorkloadClient;
use depin_sdk_types::{app::StateAnchor, error::ChainError};
use tokio::sync::Mutex;

use super::remote_state_view::DefaultAnchoredStateView;

pub struct DefaultViewResolver<V: Verifier> {
    client: Arc<WorkloadClient>,
    verifier: V,
    proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
}

impl<V: Verifier> DefaultViewResolver<V> {
    pub async fn get_genesis_root(&self) -> Result<[u8; 32], ChainError> {
        // fall back to zeros if the workload can’t answer yet
        let sr = self.client.get_state_root().await.unwrap_or_default();
        let mut out = [0u8; 32];
        let bytes = sr.as_ref();
        if bytes.len() == 32 {
            out.copy_from_slice(bytes);
        }
        Ok(out)
    }

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
        let anchor = StateAnchor(r.state_root);
        let root = depin_sdk_types::app::StateRoot(r.state_root.to_vec());
        let view = DefaultAnchoredStateView::new(
            anchor,
            root,
            self.client.clone(),
            self.verifier.clone(),
            self.proof_cache.clone(),
        );
        Ok(Arc::new(view))
    }

    async fn resolve_live(
        &self,
    ) -> Result<Arc<dyn depin_sdk_api::chain::LiveStateView>, ChainError> {
        // Not used yet; you can add a lightweight head-following view later.
        Err(ChainError::Transaction(
            "LiveStateView not implemented".into(),
        ))
    }

    async fn genesis_root(&self) -> Result<[u8; 32], ChainError> {
        self.get_genesis_root().await
    }

    fn workload_client(&self) -> &dyn Any {
        self.client.as_ref()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}