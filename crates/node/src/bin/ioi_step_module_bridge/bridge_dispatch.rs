use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};

use super::command_dispatch::dispatch_bridge_operation;
use super::command_envelope::expected_command_schema_version;
use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct BridgeEnvelope {
    #[serde(rename = "schema_version")]
    pub(super) schema_version: String,
    pub(super) operation: String,
}

pub fn run_bridge_response_from_stdin() -> Value {
    match run_bridge() {
        Ok(response) => json!({ "ok": true, "result": response }),
        Err(error) => json!({
            "ok": false,
            "error": {
                "code": error.code,
                "message": error.message,
            }
        }),
    }
}

pub(super) fn run_bridge() -> Result<Value, BridgeError> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| BridgeError::new("stdin_read_failed", error.to_string()))?;
    let raw_request: Value = serde_json::from_str(&input)
        .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
    let envelope: BridgeEnvelope = serde_json::from_value(raw_request.clone())
        .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
    let expected_schema_version =
        expected_command_schema_version(&envelope.operation).ok_or_else(|| {
            BridgeError::new(
                "operation_unknown",
                format!("unknown bridge operation {}", envelope.operation),
            )
        })?;
    if envelope.schema_version != expected_schema_version {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                expected_schema_version, envelope.schema_version
            ),
        ));
    }

    dispatch_bridge_operation(envelope.operation.as_str(), raw_request)
}
