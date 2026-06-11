use serde_json::{json, Value};
use std::io::{self, Read};

use super::command_dispatch::dispatch_bridge_operation;
use super::BridgeError;
use ioi_services::agentic::runtime::kernel::command_protocol::{
    validate_command_envelope_payload, CommandEnvelope,
};

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
    let envelope: CommandEnvelope = serde_json::from_value(raw_request.clone())
        .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
    let validated = validate_command_envelope_payload(&envelope).map_err(|error| {
        let (code, message) = error.into_parts();
        BridgeError::new(code, message)
    })?;

    dispatch_bridge_operation(validated.command_operation, raw_request)
}
