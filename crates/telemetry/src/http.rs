// Path: crates/telemetry/src/http.rs
use axum::{
    body::Bytes,
    error_handling::HandleErrorLayer,
    http::{header::CONTENT_TYPE, HeaderName, StatusCode},
    routing::get,
    Router,
};
use prometheus::{Encoder, TextEncoder};
use std::{net::SocketAddr, time::Duration};
use tokio::signal;
use tower::{BoxError, ServiceBuilder};
use tower_http::trace::TraceLayer;

async fn metrics_handler() -> ([(HeaderName, String); 1], Bytes) {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::with_capacity(1 << 20); // Pre-allocate 1MB
    encoder.encode(&metric_families, &mut buf).unwrap();
    (
        [(CONTENT_TYPE, encoder.format_type().to_string())],
        buf.into(),
    )
}

async fn healthz_handler() -> &'static str {
    "OK"
}
async fn readyz_handler() -> &'static str {
    "OK"
} // TODO: Implement readiness checks

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

    tracing::info!(target="telemetry", %addr, "listening");
    let server = axum::Server::bind(&addr).serve(app.into_make_service());
    let graceful = server.with_graceful_shutdown(async {
        signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
        tracing::info!(target = "telemetry", "shutting down gracefully");
    });

    if let Err(e) = graceful.await {
        tracing::error!(target="telemetry", error=%e, "server error");
    }
}
