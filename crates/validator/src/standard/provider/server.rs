// Path: crates/validator/src/standard/provider/server.rs

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use ioi_crypto::algorithms::hash::sha256;
use ioi_services::market::JobTicket;
use ioi_types::codec;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use super::ProviderController;

#[derive(Deserialize)]
struct ProvisionRequest {
    ticket_bytes_hex: String,
    domain_hex: String,
    ticket_root_hex: String,
}

struct AppState {
    controller: Arc<ProviderController>,
}

async fn handle_provision(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProvisionRequest>,
) -> Result<Json<super::ProvisioningReceiptData>, (StatusCode, String)> {
    // 1. Decode Inputs
    let ticket_bytes = hex::decode(&payload.ticket_bytes_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid ticket hex".into()))?;

    let domain = hex::decode(&payload.domain_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid domain hex".into()))?;

    // 2. Decode Ticket
    let ticket: JobTicket = codec::from_bytes_canonical(&ticket_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid ticket codec: {}", e),
        )
    })?;

    // 3. Verify Ticket Root Integrity (Fixes unused field warning)
    let computed_root = sha256(&ticket_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Hashing failed: {}", e),
        )
    })?;
    let computed_root_hex = hex::encode(computed_root);

    if computed_root_hex != payload.ticket_root_hex {
        return Err((
            StatusCode::BAD_REQUEST,
            "Ticket root mismatch (integrity check failed)".into(),
        ));
    }

    // 4. Delegate to Controller
    let receipt = state
        .controller
        .provision_with_domain(ticket, domain)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(receipt))
}

/// Runs the provider API server on the specified address.
pub async fn run_provider_server(controller: Arc<ProviderController>, addr: SocketAddr) {
    let app = Router::new()
        .route("/v1/provision", post(handle_provision))
        .with_state(Arc::new(AppState { controller }));

    tracing::info!("Provider API listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
