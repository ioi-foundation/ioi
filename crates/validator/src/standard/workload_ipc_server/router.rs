// Path: crates/validator/src/standard/workload_ipc_server/router.rs
use super::methods::RpcContext;
use anyhow::Result;
use depin_sdk_api::{commitment::CommitmentScheme, state::StateManager};
use futures::FutureExt;
use ipc_protocol::jsonrpc::JsonRpcError;
use serde::{de::DeserializeOwned, Serialize};
use std::{any::Any, collections::HashMap, panic::AssertUnwindSafe, sync::Arc};

/// Provides contextual information for a single RPC request.
pub struct RequestContext {
    /// The identifier of the peer that initiated the request.
    pub peer_id: String,
    /// A unique identifier for tracing the request through the system.
    pub trace_id: String,
}

/// A trait that defines the interface for a JSON-RPC method handler.
#[async_trait::async_trait]
pub trait RpcMethod: Send + Sync + 'static {
    /// The canonical, versioned name of the RPC method (e.g., "chain.getStatus.v1").
    const NAME: &'static str;
    /// The structure that defines the parameters for this method.
    type Params: DeserializeOwned + Send;
    /// The structure that defines the successful result of this method.
    type Result: Serialize + Send;
    /// The handler function that executes the method's logic.
    async fn call(
        &self,
        req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: Self::Params,
    ) -> Result<Self::Result>;
}

#[async_trait::async_trait]
pub(super) trait ErasedHandler: Send + Sync {
    async fn call(
        &self,
        req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError>;
}

#[async_trait::async_trait]
impl<T: RpcMethod> ErasedHandler for T {
    async fn call(
        &self,
        req_ctx: RequestContext,
        shared_ctx: Arc<dyn Any + Send + Sync>,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError> {
        let typed_params: T::Params = serde_json::from_value(params).map_err(|e| JsonRpcError {
            code: -32602,
            message: e.to_string(),
            data: None,
        })?;

        let fut = async {
            let res = self
                .call(req_ctx, shared_ctx, typed_params)
                .await
                .map_err(|e| JsonRpcError {
                    code: -32000,
                    message: e.to_string(),
                    data: None,
                })?;
            serde_json::to_value(res).map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("Failed to serialize RPC result: {}", e),
                data: None,
            })
        };

        match AssertUnwindSafe(fut).catch_unwind().await {
            Ok(result) => result,
            Err(panic_payload) => {
                let panic_msg = panic_payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic_payload.downcast_ref::<String>().map(|s| s.as_str()))
                    .unwrap_or("Handler panicked");
                log::error!(
                    "RPC handler for method '{}' panicked: {}",
                    T::NAME,
                    panic_msg
                );
                Err(JsonRpcError {
                    code: -32000,
                    message: "Internal server error".into(),
                    data: Some(serde_json::json!({ "details": panic_msg })),
                })
            }
        }
    }
}

/// A router for dispatching JSON-RPC requests to the appropriate method handlers.
pub struct Router {
    methods: HashMap<&'static str, Box<dyn ErasedHandler>>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    /// Creates a new, empty RPC router.
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
        }
    }
    /// Adds a new RPC method handler to the router.
    pub fn add_method<T: RpcMethod>(&mut self, method: T) {
        if self.methods.contains_key(T::NAME) {
            log::warn!("Duplicate RPC method name registered: {}", T::NAME);
        }
        self.methods.insert(T::NAME, Box::new(method));
    }
    /// Dispatches an incoming RPC request to the correct handler based on the method name.
    pub async fn dispatch<CS, ST>(
        &self,
        shared_ctx: Arc<RpcContext<CS, ST>>,
        req_ctx: RequestContext,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError>
    where
        CS: CommitmentScheme + Clone + Send + Sync + 'static,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        match self.methods.get(method) {
            Some(h) => h.call(req_ctx, shared_ctx, params).await,
            None => Err(JsonRpcError {
                code: -32601,
                message: format!("Method not found: '{method}'"),
                data: None,
            }),
        }
    }
}
