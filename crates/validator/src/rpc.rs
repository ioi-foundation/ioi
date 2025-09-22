// Path: crates/validator/src/rpc.rs
//! The JSON-RPC server for the Orchestration container.

use crate::config::OrchestrationConfig;
use anyhow::Result;
use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dashmap::DashMap;
use depin_sdk_client::WorkloadClient;
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_types::app::{ApplicationTransaction, ChainTransaction};
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
};
use tower::{limit::ConcurrencyLimitLayer, timeout::TimeoutLayer, BoxError, ServiceBuilder};

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
    Next<Body>,
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
                (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response()
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
    tx_pool: Arc<Mutex<VecDeque<ChainTransaction>>>,
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
        let (tx, status, response) = {
            let mut pool = app_state.tx_pool.lock().await;
            if pool.len() >= app_state.config.rpc_hardening.mempool_max {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    make_err(&payload.id, -32001, "Mempool is full".into()),
                );
            }

            let Some(tx_val) = extract_tx_param(&payload.params) else {
                return (
                    StatusCode::BAD_REQUEST,
                    make_err(&payload.id, -32602, "Missing transaction parameter".into()),
                );
            };

            let tx_res: Result<ChainTransaction, _> = match tx_val {
                serde_json::Value::String(s) => {
                    let bytes = hex::decode(&s)
                        .or_else(|_| BASE64_STANDARD.decode(&s))
                        .unwrap_or_else(|_| s.into_bytes());
                    serde_json::from_slice(&bytes)
                }
                other => serde_json::from_value(other),
            };
            let tx = match tx_res {
                Ok(t) => t,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
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
                    header,
                    ..
                }) => header.chain_id,
                ChainTransaction::System(sys_tx) => sys_tx.header.chain_id,
                _ => expected_chain_id,
            };
            if tx_chain_id != expected_chain_id {
                return (
                    StatusCode::BAD_REQUEST,
                    make_err(&payload.id, -32001, "Wrong chain ID".to_string()),
                );
            }

            pool.push_back(tx.clone());
            log::info!("[RPC] Admitted tx to mempool (size now: {}).", pool.len());
            (
                tx,
                StatusCode::OK,
                make_ok(&payload.id, json!("Transaction accepted")),
            )
        };

        // Kick consensus and gossip the transaction
        let _ = app_state.consensus_kick_tx.send(());
        let _ = app_state
            .swarm_command_sender
            .send(SwarmCommand::PublishTransaction(
                serde_json::to_vec(&tx).unwrap(),
            ))
            .await;
        return (status, response);
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
                        Ok(key) => match app_state.workload_client.query_raw_state(&key).await {
                            Ok(Some(value_bytes)) => (
                                StatusCode::OK,
                                make_ok(&payload.id, json!(hex::encode(value_bytes))),
                            ),
                            Ok(None) => (StatusCode::OK, make_ok(&payload.id, Value::Null)),
                            Err(e) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                make_err(&payload.id, -32000, format!("State query failed: {}", e)),
                            ),
                        },
                        Err(_) => (
                            StatusCode::BAD_REQUEST,
                            make_err(&payload.id, -32602, "Failed to decode hex key".into()),
                        ),
                    }
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        make_err(&payload.id, -32602, "Missing key parameter".into()),
                    )
                }
            }
            "query_contract" => {
                if let Params::Array(v) = &payload.params {
                    if v.len() >= 2 {
                        let address_res = v[0].as_str().and_then(|s| hex::decode(s).ok());
                        let input_res = v[1].as_str().and_then(|s| hex::decode(s).ok());
                        if let (Some(address), Some(input_data)) = (address_res, input_res) {
                            let context = depin_sdk_api::vm::ExecutionContext {
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
                                    StatusCode::INTERNAL_SERVER_ERROR,
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
                    StatusCode::BAD_REQUEST,
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
                    make_ok(&payload.id, serde_json::to_value(status).unwrap()),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    make_err(&payload.id, -32000, format!("Failed to get status: {}", e)),
                ),
            },
            _ => (
                StatusCode::NOT_FOUND,
                make_err(&payload.id, -32601, "Method not found".into()),
            ),
        }
    }
}

// --- Middleware ---
async fn enforce_post_only(req: Request<Body>, next: Next<Body>) -> Result<Response, StatusCode> {
    if req.method() != Method::POST {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    Ok(next.run(req).await)
}

async fn handle_service_error(err: BoxError) -> (StatusCode, String) {
    if err.is::<tower::timeout::error::Elapsed>() {
        (StatusCode::REQUEST_TIMEOUT, "Request timed out".to_string())
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", err),
        )
    }
}

// ---------- Server wiring ----------
pub async fn run_rpc_server(
    listen_address: &str,
    tx_pool: Arc<Mutex<VecDeque<ChainTransaction>>>,
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
        log::info!("RPC hardening and rate limiting is ENABLED.");

        let cidrs = Arc::new(
            hc.trusted_proxy_cidrs
                .iter()
                .map(|s| IpNetwork::from_str(s).expect("Invalid CIDR in trusted_proxy_cidrs"))
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
            .with_state(app_state)
            .route_layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_service_error))
                    .layer(TimeoutLayer::new(Duration::from_millis(hc.timeout_ms)))
                    .layer(ConcurrencyLimitLayer::new(hc.max_concurrency as usize)),
            )
            .layer(DefaultBodyLimit::max(hc.max_body_bytes as usize))
    } else {
        log::warn!("RPC hardening and rate limiting is DISABLED.");
        Router::new()
            .route("/rpc", post(rpc_handler))
            .with_state(app_state)
    };

    let addr: SocketAddr = listen_address.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("ORCHESTRATION_RPC_LISTENING_ON_{}", listen_address);
    log::info!("RPC server listening on {}", listen_address);

    let handle = tokio::spawn(async move {
        axum::Server::from_tcp(listener.into_std().unwrap())
            .unwrap()
            .http1_only(true) // Prevent HTTP/2 stream attacks
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });

    Ok(handle)
}
