use ioi_services::agentic::runtime::kernel::authority::{
    ExternalCapabilityExitRequest, WalletAuthorityCore,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct ExternalCapabilityExitAuthorityBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ExternalCapabilityExitRequest,
}

pub(super) fn authorize_external_capability_exit(
    request: ExternalCapabilityExitAuthorityBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = WalletAuthorityCore
        .authorize_external_capability_exit(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "external_capability_exit_authority_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_external_capability_exit_authority_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "authority": record.clone(),
        "wallet_network_grant_refs": record.wallet_network_grant_refs.clone(),
        "authority_receipt_refs": record.authority_receipt_refs.clone(),
        "authority_hash": record.authority_hash.clone(),
    }))
}
