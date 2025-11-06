// Path: crates/http-rpc-gateway/src/lib.rs
#![forbid(unsafe_code)]

use anyhow::Result;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dashmap::DashMap;
use ibc_host::IbcHost;
use ipnetwork::IpNetwork;
use once_cell::sync::OnceCell;
use prometheus::{
    exponential_buckets, register_histogram_vec, register_int_counter_vec, HistogramVec,
    IntCounterVec,
};
use serde::{Deserialize, Serialize};
use std::time::Instant as StdInstant;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Instant,
};
use tokio::sync::watch;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing;

// --- Error Handling ---
pub enum AppError {
    BadRequest(String),
    NotFound(String),
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::BadRequest(s) => (StatusCode::BAD_REQUEST, s),
            AppError::NotFound(s) => (StatusCode::NOT_FOUND, s),
            AppError::Internal(e) => {
                tracing::error!(target: "http-gateway", "Internal error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

// --- Metrics (local to gateway) ---
static GATEWAY_REQ_TOTAL: OnceCell<IntCounterVec> = OnceCell::new();
static GATEWAY_REQ_LATENCY: OnceCell<HistogramVec> = OnceCell::new();

fn install_gateway_metrics() {
    // Safe to call multiple times (OnceCell ensures single init)
    let _ = GATEWAY_REQ_TOTAL.set(
        register_int_counter_vec!(
            "ioi_ibc_gateway_requests_total",
            "Total HTTP IBC-gateway requests",
            &["chain_id", "route", "result", "height"]
        )
        .expect("register_int_counter_vec"),
    );
    let _ = GATEWAY_REQ_LATENCY.set(
        register_histogram_vec!(
            "ioi_ibc_gateway_request_duration_seconds",
            "Latency of HTTP IBC-gateway requests (seconds)",
            &["chain_id", "route", "result", "height"],
            exponential_buckets(0.001, 2.0, 15).expect("buckets")
        )
        .expect("register_histogram_vec"),
    );
}

macro_rules! get_metric {
    ($m:ident) => {
        $m.get()
            .expect("install_gateway_metrics() must be called before serving")
    };
}

#[derive(Clone)]
struct GatewayState {
    host: Arc<dyn IbcHost>,
    /// Label value for `chain_id`.
    ///
    /// Sourced from env `GATEWAY_CHAIN_ID` or defaults to "unknown" to avoid
    /// API changes to GatewayConfig.
    chain_id: String,
}

// --- Rate Limiter (copied from validator/rpc.rs) ---
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
            rps: rps as f64,
            burst: burst as f64,
            trusted_proxy_cidrs,
        }
    }
    fn client_ip<B>(&self, req: &Request<B>) -> IpAddr {
        if let Some(peer_ip) = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
        {
            if self
                .trusted_proxy_cidrs
                .iter()
                .any(|cidr| cidr.contains(peer_ip))
            {
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
async fn rate_limit_middleware(
    State(limiter): State<IpLimiter>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if limiter.allow(&req) {
        next.run(req).await
    } else {
        (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response()
    }
}

// --- Request/Response Types ---
#[derive(Deserialize)]
struct QueryRequest {
    path: String,
    height: Option<String>, // Use string to support u64
    #[serde(default)]
    latest: bool,
}

#[derive(Serialize)]
struct QueryResponse {
    value_pb: String,
    proof_pb: Option<String>,
    height: String,
}

#[derive(Deserialize)]
struct SubmitRequest {
    msgs_pb: String,
}

#[derive(Serialize)]
struct SubmitResponse {
    tx_hash: String,
}

#[derive(Deserialize)]
struct RootRequest {
    height: Option<String>,
    #[serde(default)]
    latest: bool,
}
#[derive(Serialize)]
struct RootResponse {
    root_pb: String,
    height: String,
}

// --- Handlers ---
async fn query_handler(
    State(state): State<Arc<GatewayState>>,
    Json(payload): Json<QueryRequest>,
) -> Result<Json<QueryResponse>, AppError> {
    let started = StdInstant::now();
    let height = payload
        .height
        .map(|h| h.parse::<u64>())
        .transpose()
        .map_err(|_| AppError::BadRequest("Invalid height".into()))?;
    let query_response = state
        .host
        .query(&payload.path, height, payload.latest)
        .await
        .map_err(|e| {
            // Metrics on error
            let route = "/v1/ibc/query";
            let result = "error";
            let height_label = "0";
            get_metric!(GATEWAY_REQ_TOTAL)
                .with_label_values(&[&state.chain_id, route, result, height_label])
                .inc();
            get_metric!(GATEWAY_REQ_LATENCY)
                .with_label_values(&[&state.chain_id, route, result, height_label])
                .observe(started.elapsed().as_secs_f64());
            AppError::Internal(e)
        })?;

    // Metrics on success
    let route = "/v1/ibc/query";
    let height_label = query_response.height.to_string();
    get_metric!(GATEWAY_REQ_TOTAL)
        .with_label_values(&[&state.chain_id, route, "ok", &height_label])
        .inc();
    get_metric!(GATEWAY_REQ_LATENCY)
        .with_label_values(&[&state.chain_id, route, "ok", &height_label])
        .observe(started.elapsed().as_secs_f64());

    Ok(Json(QueryResponse {
        value_pb: BASE64.encode(query_response.value),
        proof_pb: query_response.proof.map(|p| BASE64.encode(p)),
        height: query_response.height.to_string(),
    }))
}

async fn root_handler(
    State(state): State<Arc<GatewayState>>,
    Json(payload): Json<RootRequest>,
) -> Result<Json<RootResponse>, AppError> {
    let started = StdInstant::now();

    let height = payload
        .height
        .map(|h| h.parse::<u64>())
        .transpose()
        .map_err(|_| AppError::BadRequest("Invalid height".into()))?;

    let (root, h) = state
        .host
        .commitment_root(height, payload.latest)
        .await
        .map_err(|e| {
            let route = "/v1/ibc/root";
            get_metric!(GATEWAY_REQ_TOTAL)
                .with_label_values(&[&state.chain_id, route, "error", "0"])
                .inc();
            get_metric!(GATEWAY_REQ_LATENCY)
                .with_label_values(&[&state.chain_id, route, "error", "0"])
                .observe(started.elapsed().as_secs_f64());
            AppError::Internal(e)
        })?;

    let route = "/v1/ibc/root";
    let height_label = h.to_string();
    get_metric!(GATEWAY_REQ_TOTAL)
        .with_label_values(&[&state.chain_id, route, "ok", &height_label])
        .inc();
    get_metric!(GATEWAY_REQ_LATENCY)
        .with_label_values(&[&state.chain_id, route, "ok", &height_label])
        .observe(started.elapsed().as_secs_f64());

    Ok(Json(RootResponse {
        root_pb: BASE64.encode(root),
        height: height_label,
    }))
}

async fn submit_handler(
    State(state): State<Arc<GatewayState>>,
    Json(payload): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, AppError> {
    let started = StdInstant::now();
    let msgs_bytes = BASE64
        .decode(payload.msgs_pb)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    tracing::debug!(
        target = "http-gateway",
        "submit_handler: msgs_len={}",
        msgs_bytes.len()
    );

    let tx_hash = state
        .host
        .submit_ibc_messages(msgs_bytes)
        .await
        .map_err(|e| {
            let route = "/v1/ibc/submit";
            // We don't know the height on error → label "0".
            get_metric!(GATEWAY_REQ_TOTAL)
                .with_label_values(&[&state.chain_id, route, "error", "0"])
                .inc();
            get_metric!(GATEWAY_REQ_LATENCY)
                .with_label_values(&[&state.chain_id, route, "error", "0"])
                .observe(started.elapsed().as_secs_f64());
            AppError::Internal(e)
        })?;

    tracing::debug!(
        target = "http-gateway",
        "submit_handler: returned tx_hash={}",
        hex::encode(tx_hash)
    );

    // Metrics on success; height unknown at submit time -> "latest"
    let route = "/v1/ibc/submit";
    get_metric!(GATEWAY_REQ_TOTAL)
        .with_label_values(&[&state.chain_id, route, "ok", "latest"])
        .inc();
    get_metric!(GATEWAY_REQ_LATENCY)
        .with_label_values(&[&state.chain_id, route, "ok", "latest"])
        .observe(started.elapsed().as_secs_f64());

    Ok(Json(SubmitResponse {
        tx_hash: hex::encode(tx_hash),
    }))
}

// --- Server ---
pub struct GatewayConfig {
    pub listen_addr: String,
    pub rps: u32,
    pub burst: u32,
    pub body_limit_kb: usize,
    pub trusted_proxies: Vec<String>,
}

pub async fn run_server(
    config: GatewayConfig,
    host: Arc<dyn IbcHost>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    // Install metrics (no-op if already installed)
    install_gateway_metrics();

    let cidrs = Arc::new(
        config
            .trusted_proxies
            .iter()
            .filter_map(|s| IpNetwork::from_str(s).ok())
            .collect(),
    );
    let limiter = IpLimiter::new(config.rps, config.burst, cidrs);

    // Compose gateway state with a label for `chain_id`.
    // We avoid changing GatewayConfig—use env var if provided.
    let chain_id_label = std::env::var("GATEWAY_CHAIN_ID").unwrap_or_else(|_| "unknown".into());
    let state = GatewayState {
        host,
        chain_id: chain_id_label,
    };
    let state = Arc::new(state);

    let app = Router::new()
        .route("/v1/ibc/query", post(query_handler))
        .route("/v1/ibc/submit", post(submit_handler))
        .route("/v1/ibc/root", post(root_handler))
        .route_layer(middleware::from_fn_with_state(
            limiter.clone(),
            rate_limit_middleware,
        ))
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(config.body_limit_kb * 1024));

    let addr: SocketAddr = config.listen_addr.parse()?;
    tracing::info!(target: "http-gateway", "IBC HTTP Gateway listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let graceful = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_rx.changed().await.ok();
        tracing::info!(target: "http-gateway", "shutting down gracefully");
    });

    if let Err(e) = graceful.await {
        tracing::error!(target="http-gateway", error=%e, "server error");
    }

    Ok(())
}
