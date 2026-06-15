use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::io::{self, Read};

use super::{coding_tool_step_module::*, command_protocol::CommandOperation};

#[derive(Debug, Clone)]
pub struct CommandDispatchError {
    code: &'static str,
    message: String,
}

impl CommandDispatchError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone)]
pub struct CommandTransportError {
    code: &'static str,
    message: String,
}

impl CommandTransportError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

pub fn run_daemon_core_command_response_from_stdin() -> Value {
    match run_daemon_core_command_from_stdin() {
        Ok(response) => json!({ "ok": true, "result": response }),
        Err(error) => json!({
            "ok": false,
            "error": {
                "code": error.code(),
                "message": error.message(),
            }
        }),
    }
}

pub fn run_daemon_core_command_from_stdin() -> Result<Value, CommandTransportError> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| CommandTransportError::new("stdin_read_failed", error.to_string()))?;
    run_daemon_core_command_from_json_str(&input)
}

pub fn run_daemon_core_command_from_json_str(input: &str) -> Result<Value, CommandTransportError> {
    let raw_request: Value = serde_json::from_str(input)
        .map_err(|error| CommandTransportError::new("request_json_invalid", error.to_string()))?;
    run_daemon_core_command_from_value(raw_request)
}

pub fn run_daemon_core_command_from_value(
    raw_request: Value,
) -> Result<Value, CommandTransportError> {
    let envelope: super::command_protocol::CommandEnvelope =
        serde_json::from_value(raw_request.clone()).map_err(|error| {
            CommandTransportError::new("request_json_invalid", error.to_string())
        })?;
    let validated =
        super::command_protocol::validate_command_envelope_payload(&envelope).map_err(|error| {
            let (code, message) = error.into_parts();
            CommandTransportError::new(code, message)
        })?;

    dispatch_command_operation_response(validated.command_operation, raw_request)
        .map_err(|error| CommandTransportError::new(error.code(), error.message().to_string()))
}

pub fn dispatch_command_operation_response(
    command_operation: CommandOperation,
    raw_request: Value,
) -> Result<Value, CommandDispatchError> {
    match command_operation {
        CommandOperation::RunCodingToolStepModule => {
            run_coding_tool_step_module_response(decode(raw_request)?).map_err(Into::into)
        }
    }
}

fn decode<T: DeserializeOwned>(raw_request: Value) -> Result<T, CommandDispatchError> {
    serde_json::from_value(raw_request)
        .map_err(|error| CommandDispatchError::new("request_json_invalid", error.to_string()))
}

macro_rules! command_error_from {
    ($error_type:ty) => {
        impl From<$error_type> for CommandDispatchError {
            fn from(error: $error_type) -> Self {
                Self::new(error.code(), error.message().to_string())
            }
        }
    };
}

command_error_from!(CodingToolStepModuleCommandError);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::command_protocol::DAEMON_CORE_COMMAND_SCHEMA_VERSION;

    #[test]
    fn command_transport_rejects_invalid_json() {
        let error = run_daemon_core_command_from_json_str("{not-json").unwrap_err();
        assert_eq!(error.code(), "request_json_invalid");
    }

    #[test]
    fn command_transport_rejects_retired_schema_version_alias() {
        let request = json!({
            "schemaVersion": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        });
        let error = run_daemon_core_command_from_value(request).unwrap_err();
        assert_eq!(error.code(), "request_json_invalid");
    }

    #[test]
    fn command_transport_rejects_unknown_operation_before_dispatch() {
        let request = json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "unknown_operation"
        });
        let error = run_daemon_core_command_from_value(request).unwrap_err();
        assert_eq!(error.code(), "operation_unknown");
    }
}
