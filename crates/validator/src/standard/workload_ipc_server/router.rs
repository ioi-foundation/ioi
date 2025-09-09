// Path: crates/validator/src/standard/workload_ipc_server/router.rs
use super::methods::RpcContext;
use anyhow::Result;
use depin_sdk_api::{commitment::CommitmentScheme, state::StateManager};
use futures::FutureExt;
use ipc_protocol::jsonrpc::JsonRpcError;
use serde::{de::DeserializeOwned, Serialize};
use std::{any::Any, collections::HashMap, panic::AssertUnwindSafe, sync::Arc};

pub struct RequestContext {
    pub peer_id: String,
    pub trace_id: String,
}

#[async_trait::async_trait]
pub trait RpcMethod: Send + Sync + 'static {
    const NAME: &'static str;
    type Params: DeserializeOwned + Send;
    type Result: Serialize + Send;
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
                message: format!("serialize result: {e}"),
                data: None,
            })
        };

        match AssertUnwindSafe(fut).catch_unwind().await {
            Ok(result) => result,
            Err(panic_payload) => {
                let panic_msg = panic_payload
                    .downcast_ref::<&str>()
                    .copied()
                    .unwrap_or("Handler panicked");
                log::error!(
                    "RPC handler for method '{}' panicked: {}",
                    T::NAME,
                    panic_msg
                );
                Err(JsonRpcError {
                    code: -32000,
                    message: "Internal server error".into(),
                    data: None,
                })
            }
        }
    }
}

pub struct Router {
    methods: HashMap<&'static str, Box<dyn ErasedHandler>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
        }
    }
    pub fn add_method<T: RpcMethod>(&mut self, method: T) {
        if self.methods.contains_key(T::NAME) {
            panic!("Duplicate RPC method name registered: {}", T::NAME);
        }
        self.methods.insert(T::NAME, Box::new(method));
    }
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
