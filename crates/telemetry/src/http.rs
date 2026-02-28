// Path: crates/telemetry/src/http.rs
use axum::{
    body::Bytes,
    error_handling::HandleErrorLayer,
    http::{header::CONTENT_TYPE, HeaderName, StatusCode},
    routing::get,
    Router,
};
use prometheus::{Encoder, TextEncoder};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::signal;
use tower::{BoxError, ServiceBuilder};
use tower_http::trace::TraceLayer;

static TELEMETRY_READY: AtomicBool = AtomicBool::new(false);

async fn metrics_handler() -> ([(HeaderName, String); 1], Bytes) {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::with_capacity(1 << 20); // Pre-allocate 1MB
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        tracing::error!(error=%e, "Failed to encode prometheus metrics");
    }
    (
        [(CONTENT_TYPE, encoder.format_type().to_string())],
        buf.into(),
    )
}

async fn healthz_handler() -> &'static str {
    "OK"
}
async fn readyz_handler() -> (StatusCode, &'static str) {
    if TELEMETRY_READY.load(Ordering::Relaxed) {
        (StatusCode::OK, "READY")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "NOT_READY")
    }
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

pub async fn run_server(addr: SocketAddr) {
    TELEMETRY_READY.store(false, Ordering::Relaxed);
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz_handler))
        .route("/readyz", get(readyz_handler))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_service_error))
                .layer(TraceLayer::new_for_http())
                .load_shed()
                .concurrency_limit(8)
                .timeout(Duration::from_secs(2)),
        );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target = "telemetry", error = %e, "Failed to bind telemetry http server");
            return;
        }
    };
    match listener.local_addr() {
        Ok(local_addr) => tracing::info!(target = "telemetry", addr = %local_addr, "listening"),
        Err(err) => tracing::warn!(
            target = "telemetry",
            error = %err,
            "listening (failed to resolve local addr)"
        ),
    }
    TELEMETRY_READY.store(true, Ordering::Relaxed);

    let graceful = axum::serve(listener, app.into_make_service()).with_graceful_shutdown(async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(target = "telemetry", error = %e, "Failed to install CTRL+C handler");
        }
        tracing::info!(target = "telemetry", "shutting down gracefully");
        TELEMETRY_READY.store(false, Ordering::Relaxed);
    });

    if let Err(e) = graceful.await {
        tracing::error!(target="telemetry", error=%e, "server error");
    }
}
