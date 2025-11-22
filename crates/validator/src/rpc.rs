// Path: crates/validator/src/rpc.rs
//! The JSON-RPC server for the Orchestration container, handling public and
//! internal communication for transaction submission and state queries.

use crate::metrics::rpc_metrics as metrics;
// NEW: Import tx_hash module helpers
use crate::standard::orchestration::tx_hash::{hash_transaction_bytes, TxHash};
use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use dashmap::DashMap;
use ioi_api::transaction::TransactionModel;
use ioi_client::WorkloadClient;
use ioi_networking::libp2p::SwarmCommand;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::{
    app::{
        compute_interval_from_parent_state, ApplicationTransaction, BlockTimingParams,
        BlockTimingRuntime, ChainTransaction,
    },
    codec,
    keys::{BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY},
};
use ioi_types::config::OrchestrationConfig;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
    time::sleep,
};
use tower::{
    limit::ConcurrencyLimitLayer, load_shed::LoadShedLayer, timeout::TimeoutLayer, BoxError,
    ServiceBuilder,
};
use tower_http::{catch_panic::CatchPanicLayer, trace::TraceLayer};

// ---------- Simple per-IP token-bucket limiter ----------
#[derive(Clone)]
struct IpLimiter {
    buckets: Arc<DashMap<IpAddr, Bucket>>,
    rps: f64,
    burst: f64,
    trusted_proxy_cidrs: Arc<Vec<IpNetwork>>,
}
#[derive(Clone)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl IpLimiter {
    fn new(rps: u32, burst: u32, trusted_proxy_cidrs: Arc<Vec<IpNetwork>>) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            rps: rps.max(1) as f64,
            burst: burst.max(1) as f64,
            trusted_proxy_cidrs,
        }
    }
    fn client_ip<B>(&self, req: &Request<B>) -> IpAddr {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0)
            .map(|sa| sa.ip());
        if let Some(peer_ip) = peer {
            let from_trusted = self
                .trusted_proxy_cidrs
                .iter()
                .any(|cidr| cidr.contains(peer_ip));
            if from_trusted {
                if let Some(xff) = req
                    .headers()
                    .get("x-forwarded-for")
                    .and_then(|h| h.to_str().ok())
                {
                    if let Some(first) = xff.split(',').next() {
                        if let Ok(ip) = first.trim().parse::<IpAddr>() {
                            return ip;
                        }
                    }
                }
            }
            return peer_ip;
        }
        // Fallback (shouldn't happen in Axum with ConnectInfo)
        IpAddr::from([127, 0, 0, 1])
    }
    fn allow<B>(&self, req: &Request<B>) -> bool {
        let ip = self.client_ip(req);
        let now = Instant::now();
        let mut entry = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.duration_since(entry.last).as_secs_f64();
        // Refill
        entry.tokens = (entry.tokens + elapsed * self.rps).min(self.burst);
        entry.last = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn make_ip_limit_middleware(
    lim: IpLimiter,
) -> impl Fn(
    Request<Body>,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone
       + Send
       + 'static {
    move |req, next| {
        let lim = lim.clone();
        Box::pin(async move {
            if lim.allow(&req) {
                next.run(req).await
            } else {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                      "jsonrpc":"2.0","id":null,
                      "error":{"code":-32098,"message":"Too many requests"}
                    })),
                )
                    .into_response()
            }
        })
    }
}

// --- Handler Logic & Types ---
#[derive(Deserialize, Debug, Clone, Serialize, Default)]
#[serde(untagged)]
enum JsonId {
    Num(u64),
    Str(String),
    #[default]
    Null,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(untagged)]
enum Params {
    Array(Vec<serde_json::Value>),
    Object(serde_json::Map<String, serde_json::Value>),
    #[default]
    None,
}

#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    method: String,
    #[serde(default)]
    params: Params,
    #[serde(default)]
    id: JsonId,
}

struct RpcAppState {
    // MODIFIED: Type updated to tuple
    tx_pool: Arc<Mutex<VecDeque<(ChainTransaction, TxHash)>>>,
    workload_client: Arc<WorkloadClient>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    config: OrchestrationConfig,
}

fn extract_tx_param(params: &Params) -> Option<serde_json::Value> {
    match params {
        Params::Array(v) => v.first().cloned(),
        Params::Object(m) => m
            .get("tx")
            .cloned()
            .or_else(|| m.get("transaction").cloned()),
        _ => None,
    }
}

/// Checks if a client error string indicates a transient transport issue.
fn is_transient_state_err(e: &str) -> bool {
    // Be conservative; include the precise messages we’ve seen in logs.
    e.contains("Invalid JSON-RPC response")
        || e.contains("unexpected eof")
        || e.contains("close_notify")
        || e.contains("timeout")
        || e.contains("Broken pipe")
}

/// A resilient wrapper around `workload_client.query_raw_state`.
/// It retries on transient errors and downgrades persistent transport failures to `Ok(None)`.
async fn query_raw_state_resilient(
    wc: &WorkloadClient,
    key: &[u8],
) -> Result<Option<Vec<u8>>, anyhow::Error> {
    let mut backoff = 60u64; // milliseconds
    for _ in 0..3 {
        match wc.query_raw_state(key).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                let msg = e.to_string();
                if is_transient_state_err(&msg) {
                    sleep(Duration::from_millis(backoff)).await;
                    backoff *= 2;
                    continue;
                }
                // Non-transient: bubble exact error once
                return Err(anyhow!(msg));
            }
        }
    }
    // After retries, treat transient failure as “not found”
    tracing::warn!(
        target = "rpc",
        "query_state downgraded persistent IPC error to None for key {}",
        hex::encode(key)
    );
    Ok(None)
}

/// Helper function to calculate the expected timestamp for the next block.
async fn calculate_expected_timestamp(app_state: &RpcAppState) -> Result<u64, anyhow::Error> {
    let parent_status = app_state.workload_client.get_status().await?;
    let params_bytes =
        query_raw_state_resilient(&app_state.workload_client, BLOCK_TIMING_PARAMS_KEY)
            .await?
            .ok_or_else(|| anyhow!("BlockTimingParams not found in state"))?;
    let runtime_bytes =
        query_raw_state_resilient(&app_state.workload_client, BLOCK_TIMING_RUNTIME_KEY)
            .await?
            .ok_or_else(|| anyhow!("BlockTimingRuntime not found in state"))?;

    let params: BlockTimingParams = codec::from_bytes_canonical(&params_bytes)
        .map_err(|e| anyhow!("Failed to decode BlockTimingParams: {}", e))?;
    let runtime: BlockTimingRuntime = codec::from_bytes_canonical(&runtime_bytes)
        .map_err(|e| anyhow!("Failed to decode BlockTimingRuntime: {}", e))?;

    let parent_gas_used_placeholder = 0u64;
    let interval =
        compute_interval_from_parent_state(&params, &runtime, parent_status.height, parent_gas_used_placeholder);
    parent_status
        .latest_timestamp
        .checked_add(interval)
        .ok_or_else(|| anyhow!("Timestamp overflow"))
}

/// The single handler for all incoming JSON-RPC requests.
/// It dispatches to specific logic based on the method name.
async fn rpc_handler(
    headers: HeaderMap,
    State(app_state): State<Arc<RpcAppState>>,
    Json(payload): Json<JsonRpcRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Enforce JSON content type
    let ok_ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
        .unwrap_or(false);
    if !ok_ct {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(json!({"error":"expected content-type: application/json"})),
        );
    }

    // JSON-RPC response helpers
    let make_ok = |id: &JsonId, result: serde_json::Value| {
        Json(json!({"jsonrpc":"2.0","id": id, "result": result}))
    };
    let make_err = |id: &JsonId, code: i64, msg: String| {
        Json(json!({"jsonrpc":"2.0","id": id, "error": {"code": code, "message": msg}}))
    };

    let is_submit_method = matches!(
        payload.method.as_str(),
        "submit_transaction" | "submit_tx" | "broadcast_tx" | "sendTransaction"
    );

    // --- TRANSACTION SUBMISSION LOGIC ---
    if is_submit_method {
        let Some(tx_val) = extract_tx_param(&payload.params) else {
            return (
                StatusCode::OK,
                make_err(&payload.id, -32602, "Missing transaction parameter".into()),
            );
        };

        let tx_bytes = match tx_val.as_str().and_then(|s| hex::decode(s).ok()) {
            Some(bytes) => bytes,
            None => {
                return (
                    StatusCode::OK,
                    make_err(
                        &payload.id,
                        -32602,
                        "Transaction parameter must be a hex-encoded string of canonical bytes"
                            .into(),
                    ),
                )
            }
        };

        // Use a dummy model instance just for its deserialization logic.
        let dummy_model =
            UnifiedTransactionModel::new(ioi_state::primitives::hash::HashCommitmentScheme::new());
        let tx = match dummy_model.deserialize_transaction(&tx_bytes) {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::OK,
                    make_err(&payload.id, -32602, format!("Bad tx format: {}", e)),
                )
            }
        };

        let expected_chain_id = app_state.config.chain_id;
        let tx_chain_id = match &tx {
            ChainTransaction::Application(ApplicationTransaction::DeployContract {
                header,
                ..
            })
            | ChainTransaction::Application(ApplicationTransaction::CallContract {
                header, ..
            }) => header.chain_id,
            ChainTransaction::System(sys_tx) => sys_tx.header.chain_id,
            _ => expected_chain_id,
        };
        if tx_chain_id != expected_chain_id {
            return (
                StatusCode::OK,
                make_err(&payload.id, -32001, "Wrong chain ID".to_string()),
            );
        }

        // Pre-flight check via IPC to workload.
        let check_res = {
            let root_res = app_state.workload_client.get_state_root().await;
            match root_res {
                Ok(root) => {
                    let anchor_res = root.to_anchor();
                    match anchor_res {
                        Ok(anchor) => {
                            let expected_timestamp_secs =
                                match calculate_expected_timestamp(&app_state).await {
                                    Ok(ts) => ts,
                                    Err(e) => {
                                        return (
                                            StatusCode::OK,
                                            make_err(
                                                &payload.id,
                                                -32000,
                                                format!(
                                                    "Failed to determine next block timestamp: {}",
                                                    e
                                                ),
                                            ),
                                        );
                                    }
                                };
                            app_state
                                .workload_client
                                .check_transactions_at(
                                    anchor,
                                    expected_timestamp_secs,
                                    vec![tx.clone()],
                                )
                                .await
                        }
                        Err(e) => Err(anyhow!("Failed to create anchor from root: {}", e)),
                    }
                }
                Err(e) => Err(anyhow!("Failed to get state root for pre-check: {}", e)),
            }
        };

        match check_res {
            Ok(results) => {
                if let Some(Err(e)) = results.first() {
                    return (
                        StatusCode::OK,
                        make_err(
                            &payload.id,
                            -32000,
                            format!("Transaction rejected by pre-check: {}", e),
                        ),
                    );
                }
            }
            Err(e) => {
                return (
                    StatusCode::OK,
                    make_err(
                        &payload.id,
                        -32000,
                        format!("Transaction pre-check failed: {}", e),
                    ),
                );
            }
        }

        {
            let mut pool = app_state.tx_pool.lock().await;
            metrics().set_mempool_size(pool.len() as f64);
            if pool.len() >= app_state.config.rpc_hardening.mempool_max {
                return (
                    StatusCode::OK,
                    make_err(&payload.id, -32001, "Mempool is full".into()),
                );
            }
            
            // MODIFIED: Compute hash using helper
            let tx_hash = match hash_transaction_bytes(&tx_bytes) {
                Ok(h) => h,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, make_err(&payload.id, -32603, format!("Hashing failed: {}", e))),
            };

            // MODIFIED: Push tuple
            pool.push_back((tx, tx_hash));
            metrics().inc_mempool_transactions_added();
            metrics().set_mempool_size(pool.len() as f64);
            tracing::info!(target: "rpc", event = "mempool_add", new_size = pool.len());
        }

        // Kick consensus and gossip the canonical transaction bytes
        let _ = app_state.consensus_kick_tx.send(());
        let _ = app_state
            .swarm_command_sender
            .send(SwarmCommand::PublishTransaction(tx_bytes))
            .await;

        (
            StatusCode::OK,
            make_ok(&payload.id, json!("Transaction accepted")),
        )
    } else {
        // --- QUERY LOGIC ---
        match payload.method.as_str() {
            "query_state" => {
                let key_hex_opt = match &payload.params {
                    Params::Array(v) => v.first().and_then(|x| x.as_str()),
                    _ => None,
                };
                if let Some(key_hex) = key_hex_opt {
                    match hex::decode(key_hex) {
                        Ok(key) => {
                            match query_raw_state_resilient(&app_state.workload_client, &key).await
                            {
                                Ok(Some(value_bytes)) => (
                                    StatusCode::OK,
                                    make_ok(&payload.id, json!(hex::encode(value_bytes))),
                                ),
                                Ok(None) => (StatusCode::OK, make_ok(&payload.id, Value::Null)),
                                Err(e) => (
                                    StatusCode::OK,
                                    make_err(
                                        &payload.id,
                                        -32000,
                                        format!("State query failed: {}", e),
                                    ),
                                ),
                            }
                        }
                        Err(_) => (
                            StatusCode::OK,
                            make_err(&payload.id, -32602, "Failed to decode hex key".into()),
                        ),
                    }
                } else {
                    (
                        StatusCode::OK,
                        make_err(&payload.id, -32602, "Missing key parameter".into()),
                    )
                }
            }
            "query_contract" => {
                if let Params::Array(v) = &payload.params {
                    if let (Some(addr_val), Some(input_val)) = (v.get(0), v.get(1)) {
                        let address_res = addr_val.as_str().and_then(|s| hex::decode(s).ok());
                        let input_res = input_val.as_str().and_then(|s| hex::decode(s).ok());
                        if let (Some(address), Some(input_data)) = (address_res, input_res) {
                            let context = ioi_api::vm::ExecutionContext {
                                caller: vec![],
                                block_height: 0,
                                gas_limit: app_state.config.default_query_gas_limit,
                                contract_address: vec![],
                            };
                            return match app_state
                                .workload_client
                                .query_contract(address, input_data, context)
                                .await
                            {
                                Ok(output) => (
                                    StatusCode::OK,
                                    make_ok(&payload.id, json!(hex::encode(output.return_data))),
                                ),
                                Err(e) => (
                                    StatusCode::OK,
                                    make_err(
                                        &payload.id,
                                        -32000,
                                        format!("Contract query failed: {}", e),
                                    ),
                                ),
                            };
                        }
                    }
                }
                (
                    StatusCode::OK,
                    make_err(
                        &payload.id,
                        -32602,
                        "Invalid params for query_contract".into(),
                    ),
                )
            }
            "system.getStatus.v1" => match app_state.workload_client.get_status().await {
                Ok(status) => (
                    StatusCode::OK,
                    make_ok(
                        &payload.id,
                        serde_json::to_value(status)
                            .unwrap_or_else(|_| json!({"error": "serialization failed"})),
                    ),
                ),
                Err(e) => (
                    StatusCode::OK,
                    make_err(&payload.id, -32000, format!("Failed to get status: {}", e)),
                ),
            },
            "chain.getBlockByHeight.v1" => {
                let height = match &payload.params {
                    Params::Object(m) => m.get("height").and_then(|v| v.as_u64()),
                    _ => None,
                };
                let Some(height) = height else {
                    return (
                        StatusCode::OK,
                        make_err(
                            &payload.id,
                            -32602,
                            "Missing/invalid 'height' parameter".into(),
                        ),
                    );
                };
                match app_state.workload_client.get_block_by_height(height).await {
                    Ok(block_opt) => {
                        let result_value = match serde_json::to_value(block_opt) {
                            Ok(v) => v,
                            Err(_) => json!({"error": "serialization failed"}),
                        };
                        (StatusCode::OK, make_ok(&payload.id, result_value))
                    }
                    Err(e) => (
                        StatusCode::OK,
                        make_err(
                            &payload.id,
                            -32000,
                            format!("getBlockByHeight failed: {}", e),
                        ),
                    ),
                }
            }
            "state.queryStateAt.v1" => {
                let (root, key) = match &payload.params {
                    Params::Object(m) => {
                        let root_val = m.get("root").cloned();
                        let key_val = m.get("key").cloned();
                        (root_val, key_val)
                    }
                    _ => (None, None),
                };

                let (Some(root), Some(key)) = (root, key) else {
                    return (
                        StatusCode::OK,
                        make_err(
                            &payload.id,
                            -32602,
                            "Missing 'root' or 'key' parameters".into(),
                        ),
                    );
                };

                let root_obj_res = serde_json::from_value(root);
                let key_bytes_res: Result<Vec<u8>, _> = serde_json::from_value(key);

                if let (Ok(root_obj), Ok(key_bytes)) = (root_obj_res, key_bytes_res) {
                    match app_state
                        .workload_client
                        .query_state_at(root_obj, &key_bytes)
                        .await
                    {
                        Ok(resp) => (
                            StatusCode::OK,
                            make_ok(
                                &payload.id,
                                serde_json::to_value(resp)
                                    .unwrap_or_else(|_| json!({"error": "serialization failed"})),
                            ),
                        ),
                        Err(e) => (
                            StatusCode::OK,
                            make_err(&payload.id, -32000, format!("queryStateAt failed: {}", e)),
                        ),
                    }
                } else {
                    (
                        StatusCode::OK,
                        make_err(
                            &payload.id,
                            -32602,
                            "Invalid 'root' or 'key' parameter format".into(),
                        ),
                    )
                }
            }
            _ => (
                StatusCode::OK,
                make_err(&payload.id, -32601, "Method not found".into()),
            ),
        }
    }
}

// --- Middleware ---
async fn enforce_post_only(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    if req.method() != Method::POST {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    Ok(next.run(req).await)
}

async fn handle_service_error(err: BoxError) -> impl IntoResponse {
    if err.is::<tower::timeout::error::Elapsed>() {
        (
            StatusCode::REQUEST_TIMEOUT,
            Json(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32000, "message": "Request timed out"}}),
            ),
        )
    } else if err.is::<tower::load_shed::error::Overloaded>() {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32099, "message": "Service overloaded"}}),
            ),
        )
    } else {
        let bt = std::backtrace::Backtrace::capture();
        tracing::error!(target="rpc", error=%err, backtrace=?bt, "Unhandled internal error in RPC middleware");

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32603, "message": "Internal server error"}}),
            ),
        )
    }
}

async fn track_rpc_metrics(req: Request<Body>, next: Next) -> Response {
    let start = Instant::now();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();
    let response = next.run(req).await;
    metrics().observe_request_duration(&route, start.elapsed().as_secs_f64());
    metrics().inc_requests_total(&route, response.status().as_u16());
    response
}

// ---------- Server wiring ----------
/// Initializes and runs the JSON-RPC server for the Orchestration container.
///
/// This server exposes endpoints for transaction submission (`/rpc/submit`) and
/// state queries (`/rpc/query`). It includes middleware for rate limiting,
/// timeout, concurrency control, and logging, which can be configured via
/// `orchestration.toml`.
pub async fn run_rpc_server(
    listen_address: &str,
    // MODIFIED: Type updated
    tx_pool: Arc<Mutex<VecDeque<(ChainTransaction, TxHash)>>>,
    workload_client: Arc<WorkloadClient>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    config: OrchestrationConfig,
) -> Result<JoinHandle<()>> {
    let app_state = Arc::new(RpcAppState {
        tx_pool,
        workload_client,
        swarm_command_sender,
        consensus_kick_tx,
        config: config.clone(),
    });

    let hc = &config.rpc_hardening;

    let app = if hc.enabled {
        tracing::info!(target: "rpc", "RPC hardening and rate limiting is ENABLED.");

        let cidrs = Arc::new(
            hc.trusted_proxy_cidrs
                .iter()
                .filter_map(|s| {
                    IpNetwork::from_str(s)
                        .map_err(|e| {
                            tracing::error!("Invalid CIDR in trusted_proxy_cidrs: {}", e);
                            e
                        })
                        .ok()
                })
                .collect::<Vec<_>>(),
        );

        let submit_limiter = make_ip_limit_middleware(IpLimiter::new(
            hc.submit_rps,
            hc.submit_burst,
            cidrs.clone(),
        ));
        let query_limiter =
            make_ip_limit_middleware(IpLimiter::new(hc.query_rps, hc.query_burst, cidrs));

        Router::new()
            .route("/rpc/submit", post(rpc_handler))
            .route_layer(middleware::from_fn(submit_limiter))
            .route("/rpc/query", post(rpc_handler))
            .route_layer(middleware::from_fn(query_limiter.clone()))
            .route("/rpc", post(rpc_handler))
            .route_layer(middleware::from_fn(query_limiter)) // Legacy endpoint gets query limits
            .route_layer(middleware::from_fn(enforce_post_only))
            .route_layer(middleware::from_fn(track_rpc_metrics))
            .with_state(app_state)
            .layer(
                ServiceBuilder::new()
                    .layer(CatchPanicLayer::new())
                    .layer(middleware::map_response(|mut _res: Response| async move {
                        if _res.status() == StatusCode::INTERNAL_SERVER_ERROR {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({
                                  "jsonrpc":"2.0","id": null,
                                  "error":{"code": -32603, "message":"Internal server error"}
                                })),
                            )
                                .into_response();
                        }
                        _res
                    }))
                    .layer(HandleErrorLayer::new(handle_service_error))
                    .layer(TraceLayer::new_for_http())
                    .layer(LoadShedLayer::new())
                    .layer(TimeoutLayer::new(Duration::from_millis(hc.timeout_ms)))
                    .layer(ConcurrencyLimitLayer::new(hc.max_concurrency as usize)),
            )
            .layer(DefaultBodyLimit::max(hc.max_body_bytes as usize))
    } else {
        tracing::warn!(target: "rpc", "RPC hardening and rate limiting is DISABLED.");
        Router::new()
            .route("/rpc", post(rpc_handler))
            .with_state(app_state)
    };

    let addr: SocketAddr = listen_address.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("ORCHESTRATION_RPC_LISTENING_ON_{}", listen_address);
    tracing::info!(target: "rpc", listen_addr = %listen_address, "RPC server listening");

    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok(); // Log error instead of panicking
    });

    Ok(handle)
}