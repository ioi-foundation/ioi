use serde::Deserialize;
use serde_json::{json, Value};

pub const RUNTIME_MEMORY_COMMAND_PLAN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-command-plan-request.v1";
pub const RUNTIME_MEMORY_COMMAND_PLAN_SCHEMA_VERSION: &str = "ioi.runtime.memory-command-plan.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeMemoryCommandPlanRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMemoryCommandPlanError {
    code: &'static str,
    message: String,
}

impl RuntimeMemoryCommandPlanError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
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

#[derive(Debug, Clone, Default)]
pub struct RuntimeMemoryCommandPlanCore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeMemoryCommand {
    None,
    Show,
    Disable,
    Enable,
    Path,
    Remember { text: String },
    Edit { id: String, text: String },
    Delete { id: String },
}

#[derive(Debug, Clone)]
pub struct RuntimeMemoryCommandPlanRecord {
    pub operation: String,
    pub operation_kind: String,
    pub command: RuntimeMemoryCommand,
    pub thread_id: Option<String>,
    pub agent_id: Option<String>,
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

pub fn plan_runtime_memory_command_plan_api_response(
    request: RuntimeMemoryCommandPlanRequest,
) -> Result<Value, RuntimeMemoryCommandPlanError> {
    let record = RuntimeMemoryCommandPlanCore.plan(&request)?;
    Ok(json!({
        "source": "rust_runtime_memory_command_plan_api",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeMemoryCommandPlanCore {
    pub fn plan(
        &self,
        request: &RuntimeMemoryCommandPlanRequest,
    ) -> Result<RuntimeMemoryCommandPlanRecord, RuntimeMemoryCommandPlanError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_MEMORY_COMMAND_PLAN_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeMemoryCommandPlanError::new(
                    "runtime_memory_command_plan_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_MEMORY_COMMAND_PLAN_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }
        if let Some(operation) = optional_trimmed(request.operation.as_deref()) {
            if operation != "runtime_memory_command_plan" {
                return Err(RuntimeMemoryCommandPlanError::new(
                    "runtime_memory_command_plan_operation_invalid",
                    "run-memory command planning requires runtime_memory_command_plan",
                ));
            }
        }
        if let Some(operation_kind) = optional_trimmed(request.operation_kind.as_deref()) {
            if operation_kind != "memory.run_command.plan" {
                return Err(RuntimeMemoryCommandPlanError::new(
                    "runtime_memory_command_plan_operation_kind_invalid",
                    "run-memory command planning requires memory.run_command.plan",
                ));
            }
        }
        let command = parse_runtime_memory_command(request.prompt.as_deref().unwrap_or_default());
        Ok(RuntimeMemoryCommandPlanRecord {
            operation: "runtime_memory_command_plan".to_string(),
            operation_kind: "memory.run_command.plan".to_string(),
            command,
            thread_id: optional_trimmed(request.thread_id.as_deref()),
            agent_id: optional_trimmed(request.agent_id.as_deref()),
            source: optional_trimmed(request.source.as_deref()),
            evidence_refs: vec![
                "rust_daemon_core_memory_command_parser".to_string(),
                "runtime_memory_command_parser_js_retired".to_string(),
                "run_memory_command_grammar_rust_owned".to_string(),
            ],
            receipt_refs: vec!["receipt_runtime_memory_command_plan".to_string()],
        })
    }
}

impl RuntimeMemoryCommandPlanRecord {
    pub fn command_kind(&self) -> &'static str {
        self.command.kind()
    }

    pub fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_MEMORY_COMMAND_PLAN_SCHEMA_VERSION,
            "object": "ioi.runtime_memory_command_plan",
            "status": "planned",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "command_kind": self.command_kind(),
            "thread_id": self.thread_id,
            "agent_id": self.agent_id,
            "source": self.source,
            "command": self.command.to_value(),
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

impl RuntimeMemoryCommand {
    fn kind(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Show => "show",
            Self::Disable => "disable",
            Self::Enable => "enable",
            Self::Path => "path",
            Self::Remember { .. } => "remember",
            Self::Edit { .. } => "edit",
            Self::Delete { .. } => "delete",
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::None | Self::Show | Self::Disable | Self::Enable | Self::Path => {
                json!({ "kind": self.kind() })
            }
            Self::Remember { text } => json!({ "kind": self.kind(), "text": text }),
            Self::Edit { id, text } => {
                json!({ "kind": self.kind(), "id": id, "text": text })
            }
            Self::Delete { id } => json!({ "kind": self.kind(), "id": id }),
        }
    }
}

fn parse_runtime_memory_command(prompt: &str) -> RuntimeMemoryCommand {
    let text = prompt.trim();
    if let Some(after_hash) = text.strip_prefix('#') {
        if let Some(rest) =
            strip_ascii_keyword_with_required_space(after_hash.trim_start(), "remember")
        {
            let remembered = rest.trim();
            if !remembered.is_empty() {
                return RuntimeMemoryCommand::Remember {
                    text: remembered.to_string(),
                };
            }
        }
    }
    let Some(rest) = strip_ascii_keyword(text, "/memory") else {
        return RuntimeMemoryCommand::None;
    };
    let body = rest.trim();
    if body.is_empty() || body.eq_ignore_ascii_case("show") {
        return RuntimeMemoryCommand::Show;
    }
    if body.eq_ignore_ascii_case("disable") {
        return RuntimeMemoryCommand::Disable;
    }
    if body.eq_ignore_ascii_case("enable") {
        return RuntimeMemoryCommand::Enable;
    }
    if body.eq_ignore_ascii_case("path") {
        return RuntimeMemoryCommand::Path;
    }
    if let Some(edit_body) = strip_ascii_keyword_with_required_space(body, "edit") {
        let edit_body = edit_body.trim();
        if let Some((id, replacement)) = split_first_ascii_token(edit_body) {
            let replacement = replacement.trim();
            if !id.is_empty() && !replacement.is_empty() {
                return RuntimeMemoryCommand::Edit {
                    id: id.to_string(),
                    text: replacement.to_string(),
                };
            }
        }
    }
    for delete_keyword in ["delete", "remove", "forget"] {
        if let Some(delete_body) = strip_ascii_keyword_with_required_space(body, delete_keyword) {
            let id = delete_body.trim();
            if !id.is_empty() && !id.chars().any(char::is_whitespace) {
                return RuntimeMemoryCommand::Delete { id: id.to_string() };
            }
        }
    }
    RuntimeMemoryCommand::None
}

fn strip_ascii_keyword<'a>(value: &'a str, keyword: &str) -> Option<&'a str> {
    if value.len() < keyword.len() {
        return None;
    }
    let (head, rest) = value.split_at(keyword.len());
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    if rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace) {
        Some(rest)
    } else {
        None
    }
}

fn strip_ascii_keyword_with_required_space<'a>(value: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = strip_ascii_keyword(value, keyword)?;
    if rest.chars().next().is_some_and(char::is_whitespace) {
        Some(rest)
    } else {
        None
    }
}

fn split_first_ascii_token(value: &str) -> Option<(&str, &str)> {
    let trimmed = value.trim_start();
    let split_at = trimmed.find(char::is_whitespace)?;
    Some((&trimmed[..split_at], &trimmed[split_at..]))
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(prompt: &str) -> RuntimeMemoryCommandPlanRequest {
        RuntimeMemoryCommandPlanRequest {
            schema_version: Some(RUNTIME_MEMORY_COMMAND_PLAN_REQUEST_SCHEMA_VERSION.to_string()),
            operation: Some("runtime_memory_command_plan".to_string()),
            operation_kind: Some("memory.run_command.plan".to_string()),
            prompt: Some(prompt.to_string()),
            thread_id: Some("thread_123".to_string()),
            agent_id: Some("agent_123".to_string()),
            source: Some("runtime_run_memory_resolution".to_string()),
        }
    }

    #[test]
    fn rust_plans_run_memory_command_grammar() {
        let cases = [
            (
                "# remember Deploy window is Friday",
                json!({ "kind": "remember", "text": "Deploy window is Friday" }),
            ),
            (
                "#remember deploy",
                json!({ "kind": "remember", "text": "deploy" }),
            ),
            ("/memory", json!({ "kind": "show" })),
            ("/memory show", json!({ "kind": "show" })),
            ("/memory disable", json!({ "kind": "disable" })),
            ("/memory enable", json!({ "kind": "enable" })),
            ("/memory path", json!({ "kind": "path" })),
            (
                "/memory edit memory_123 New value",
                json!({ "kind": "edit", "id": "memory_123", "text": "New value" }),
            ),
            (
                "/memory remove memory_123",
                json!({ "kind": "delete", "id": "memory_123" }),
            ),
            ("ordinary prompt", json!({ "kind": "none" })),
        ];
        for (prompt, expected) in cases {
            let record = RuntimeMemoryCommandPlanCore
                .plan(&request(prompt))
                .expect("plan memory command");
            assert_eq!(record.command.to_value(), expected, "{prompt}");
            assert_eq!(record.operation_kind, "memory.run_command.plan");
            assert_eq!(record.thread_id.as_deref(), Some("thread_123"));
            assert!(record
                .evidence_refs
                .contains(&"runtime_memory_command_parser_js_retired".to_string()));
        }
    }

    #[test]
    fn rust_rejects_unowned_run_memory_command_plan_transport() {
        let error = RuntimeMemoryCommandPlanCore
            .plan(&RuntimeMemoryCommandPlanRequest {
                operation: Some("parse_memory_command".to_string()),
                ..request("#remember deploy")
            })
            .expect_err("retired operation must be rejected");
        assert_eq!(
            error.code(),
            "runtime_memory_command_plan_operation_invalid"
        );
    }

    #[test]
    fn rust_shapes_runtime_memory_command_plan_api_response() {
        let response = plan_runtime_memory_command_plan_api_response(request("#remember deploy"))
            .expect("memory command plan response");
        assert_eq!(response["source"], "rust_runtime_memory_command_plan_api");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(
            response["record"]["object"],
            "ioi.runtime_memory_command_plan"
        );
        assert_eq!(
            response["record"]["operation_kind"],
            "memory.run_command.plan"
        );
        assert_eq!(response["record"]["command_kind"], "remember");
        assert_eq!(response["record"]["command"]["text"], "deploy");
    }
}
