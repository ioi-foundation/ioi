use ioi_services::agentic::runtime::kernel::authority::{
    ExternalCapabilityExitRequest, WalletAuthorityCore,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BridgeError, DAEMON_CORE_COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct ExternalCapabilityExitAuthorityBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ExternalCapabilityExitRequest,
}

pub(super) fn authorize_external_capability_exit(
    request: ExternalCapabilityExitAuthorityBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "authorize_external_capability_exit" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
