use serde_json::{json, Value};
use std::io::{self, Read};

use ioi_services::agentic::runtime::kernel::command_dispatch::dispatch_command_operation_response;
use ioi_services::agentic::runtime::kernel::command_protocol::{
    validate_command_envelope_payload, CommandEnvelope,
};

#[derive(Debug)]
struct BridgeError {
    code: &'static str,
    message: String,
}

impl BridgeError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }
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

fn run_bridge() -> Result<Value, BridgeError> {
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

    dispatch_command_operation_response(validated.command_operation, raw_request)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}
