use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.conversation-artifact-control-request.v1";
pub const RUNTIME_CONVERSATION_ARTIFACT_CONTROL_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime_conversation_artifact_control.v1";
const CONVERSATION_ARTIFACT_SCHEMA_VERSION: &str = "ioi.conversation_artifact.v1";
const CONVERSATION_ARTIFACT_REVISION_SCHEMA_VERSION: &str = "ioi.conversation_artifact_revision.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeConversationArtifactControlRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub artifacts: Value,
    #[serde(default)]
    pub artifact: Value,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConversationArtifactControlCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeConversationArtifactControlCommandError {
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
pub struct RuntimeConversationArtifactControlCore;

#[derive(Debug, Clone)]
pub struct RuntimeConversationArtifactControlRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: Option<String>,
    pub artifact_id: String,
    pub artifact: Value,
    pub result: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

pub fn plan_runtime_conversation_artifact_control_response(
    request: RuntimeConversationArtifactControlRequest,
) -> Result<Value, RuntimeConversationArtifactControlCommandError> {
    let record = RuntimeConversationArtifactControlCore::default().plan(&request)?;
    Ok(json!({
        "source": "rust_runtime_conversation_artifact_control_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeConversationArtifactControlCore {
    pub fn plan(
        &self,
        request: &RuntimeConversationArtifactControlRequest,
    ) -> Result<
        RuntimeConversationArtifactControlRecord,
        RuntimeConversationArtifactControlCommandError,
    > {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeConversationArtifactControlCommandError::new(
                    "runtime_conversation_artifact_control_schema_version_invalid",
                    "conversation artifact control request schema_version is not owned by this Rust core",
                ));
            }
        }

        let operation_kind = normalized_operation_kind(request)?;
        let operation = optional_trimmed(request.operation.as_deref()).unwrap_or_else(|| {
            match operation_kind.as_str() {
                "artifact.conversation.create" => "conversation_artifact_create",
                "artifact.conversation.action" => "conversation_artifact_action",
                "artifact.conversation.export" => "conversation_artifact_export",
                "artifact.conversation.promote" => "conversation_artifact_promote",
                _ => "conversation_artifact_control",
            }
            .to_string()
        });
        let created_at = string_field(&request.request, "created_at")
            .or_else(|| string_field(&request.request, "updated_at"))
            .unwrap_or_else(|| "rust_policy_core".to_string());
        let mut evidence_refs = string_vec(&request.evidence_refs);
        if evidence_refs.is_empty() {
            evidence_refs = vec![
                "runtime_conversation_artifact_control_rust_owned".to_string(),
                "runtime_conversation_artifact_state_commit_rust_owned".to_string(),
                "agentgres_conversation_artifact_truth_required".to_string(),
            ];
        }

        let mut policy_decision_refs = string_vec(&request.policy_decision_refs);
        if policy_decision_refs.is_empty() {
            policy_decision_refs = vec![format!(
                "policy_conversation_artifact_control_allow_{}",
                short_hash(&format!("{operation_kind}:{created_at}"))
            )];
        }

        let (artifact, result, artifact_id_seed) = match operation_kind.as_str() {
            "artifact.conversation.create" => {
                let thread_id =
                    optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
                        RuntimeConversationArtifactControlCommandError::new(
                            "runtime_conversation_artifact_control_thread_id_required",
                            "conversation artifact create requires thread_id",
                        )
                    })?;
                let idempotency_key = string_field(&request.request, "idempotency_key")
                    .unwrap_or_else(|| format!("thread:{thread_id}:conversation-artifact"));
                let artifact_id =
                    optional_trimmed(request.artifact_id.as_deref()).unwrap_or_else(|| {
                        format!(
                            "conversation_artifact_{}",
                            short_hash(&format!("{thread_id}:{idempotency_key}:{created_at}"))
                        )
                    });
                let artifact = created_artifact(
                    &artifact_id,
                    &thread_id,
                    &created_at,
                    &request.request,
                    &evidence_refs,
                );
                let result = json!({
                    "status": "created",
                    "operation_kind": operation_kind,
                    "artifact_id": artifact_id,
                    "artifact": artifact,
                });
                (artifact, result, artifact_id)
            }
            "artifact.conversation.action" => {
                let artifact_id = required_artifact_id(request)?;
                let mut artifact = existing_artifact(request, &artifact_id)?;
                apply_action(&mut artifact, &artifact_id, &created_at, &request.request)?;
                let result = json!({
                    "status": "completed",
                    "operation_kind": operation_kind,
                    "artifact_id": artifact_id,
                    "action_kind": string_field(&request.request, "action_kind").unwrap_or_else(|| "update".to_string()),
                    "artifact": artifact,
                });
                (artifact, result, artifact_id)
            }
            "artifact.conversation.export" => {
                let artifact_id = required_artifact_id(request)?;
                let mut artifact = existing_artifact(request, &artifact_id)?;
                let export_ref = format!(
                    "artifact-export://{artifact_id}/{}",
                    short_hash(&format!("{artifact_id}:export:{created_at}"))
                );
                push_unique_string(&mut artifact, "export_refs", export_ref.clone());
                set_string(&mut artifact, "updated_at", &created_at);
                let result = json!({
                    "status": "exported",
                    "operation_kind": operation_kind,
                    "artifact_id": artifact_id,
                    "export_ref": export_ref,
                    "export_format": string_field(&request.request, "export_format").unwrap_or_else(|| "artifact".to_string()),
                    "artifact": artifact,
                });
                (artifact, result, artifact_id)
            }
            "artifact.conversation.promote" => {
                let artifact_id = required_artifact_id(request)?;
                let mut artifact = existing_artifact(request, &artifact_id)?;
                let promotion_ref = format!(
                    "artifact-promotion://{artifact_id}/{}",
                    short_hash(&format!("{artifact_id}:promote:{created_at}"))
                );
                push_unique_string(&mut artifact, "promotion_refs", promotion_ref.clone());
                set_string(&mut artifact, "updated_at", &created_at);
                let result = json!({
                    "status": "promoted",
                    "operation_kind": operation_kind,
                    "artifact_id": artifact_id,
                    "promotion_ref": promotion_ref,
                    "promotion_target": string_field(&request.request, "promotion_target").unwrap_or_else(|| "runtime".to_string()),
                    "artifact": artifact,
                });
                (artifact, result, artifact_id)
            }
            _ => {
                return Err(RuntimeConversationArtifactControlCommandError::new(
                    "runtime_conversation_artifact_control_operation_kind_unsupported",
                    format!(
                        "unsupported conversation artifact control operation kind {operation_kind}"
                    ),
                ));
            }
        };

        let receipt_refs = receipt_refs(request, &artifact_id_seed, &operation_kind);
        let mut artifact = artifact;
        set_array_strings(&mut artifact, "receipt_refs", &receipt_refs);
        set_array_strings(&mut artifact, "policy_refs", &policy_decision_refs);
        set_array_strings(&mut artifact, "evidence_refs", &evidence_refs);

        Ok(RuntimeConversationArtifactControlRecord {
            operation,
            operation_kind,
            thread_id: optional_trimmed(request.thread_id.as_deref()).or_else(|| {
                artifact
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            }),
            artifact_id: artifact_id_seed,
            artifact,
            result,
            receipt_refs,
            policy_decision_refs,
            evidence_refs,
        })
    }
}

impl RuntimeConversationArtifactControlRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_CONVERSATION_ARTIFACT_CONTROL_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_conversation_artifact_control",
            "status": "planned",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "thread_id": self.thread_id,
            "artifact_id": self.artifact_id,
            "artifact": self.artifact,
            "result": self.result,
            "receipt_refs": self.receipt_refs,
            "policy_decision_refs": self.policy_decision_refs,
            "evidence_refs": self.evidence_refs,
        })
    }
}

fn normalized_operation_kind(
    request: &RuntimeConversationArtifactControlRequest,
) -> Result<String, RuntimeConversationArtifactControlCommandError> {
    optional_trimmed(request.operation_kind.as_deref()).ok_or_else(|| {
        RuntimeConversationArtifactControlCommandError::new(
            "runtime_conversation_artifact_control_operation_kind_required",
            "conversation artifact control requires operation_kind",
        )
    })
}

fn required_artifact_id(
    request: &RuntimeConversationArtifactControlRequest,
) -> Result<String, RuntimeConversationArtifactControlCommandError> {
    optional_trimmed(request.artifact_id.as_deref()).ok_or_else(|| {
        RuntimeConversationArtifactControlCommandError::new(
            "runtime_conversation_artifact_control_artifact_id_required",
            "conversation artifact control requires artifact_id",
        )
    })
}

fn existing_artifact(
    request: &RuntimeConversationArtifactControlRequest,
    artifact_id: &str,
) -> Result<Value, RuntimeConversationArtifactControlCommandError> {
    if request.artifact.is_object() && matches_artifact_id(&request.artifact, artifact_id) {
        return Ok(request.artifact.clone());
    }
    artifact_candidates(&request.artifacts)
        .into_iter()
        .find(|record| matches_artifact_id(record, artifact_id))
        .ok_or_else(|| {
            RuntimeConversationArtifactControlCommandError::new(
                "runtime_conversation_artifact_control_artifact_not_found",
                format!(
                    "conversation artifact {artifact_id} was not found in Rust control candidates"
                ),
            )
        })
}

fn created_artifact(
    artifact_id: &str,
    thread_id: &str,
    created_at: &str,
    request: &Value,
    evidence_refs: &[String],
) -> Value {
    let title = string_field(request, "title").unwrap_or_else(|| "Untitled artifact".to_string());
    let artifact_class =
        string_field(request, "artifact_class").unwrap_or_else(|| "conversation".to_string());
    let output_modality =
        string_field(request, "output_modality").unwrap_or_else(|| "document".to_string());
    let revision = revision(artifact_id, created_at, request);
    json!({
        "schema_version": CONVERSATION_ARTIFACT_SCHEMA_VERSION,
        "object": "ioi.conversation_artifact",
        "id": artifact_id,
        "artifact_id": artifact_id,
        "thread_id": thread_id,
        "title": title,
        "artifact_class": artifact_class,
        "output_modality": output_modality,
        "state_label": string_field(request, "state_label").unwrap_or_else(|| "draft".to_string()),
        "status": "active",
        "created_at": created_at,
        "updated_at": created_at,
        "latest_revision_id": revision["revision_id"].clone(),
        "revisions": [revision],
        "source_refs": array_strings_field(request, "source_refs"),
        "original_refs": array_strings_field(request, "original_refs"),
        "projection_refs": array_strings_field(request, "projection_refs"),
        "preview_refs": array_strings_field(request, "preview_refs"),
        "trace_refs": array_strings_field(request, "trace_refs"),
        "policy_refs": array_strings_field(request, "policy_refs"),
        "receipt_refs": array_strings_field(request, "receipt_refs"),
        "evidence_refs": evidence_refs,
    })
}

fn apply_action(
    artifact: &mut Value,
    artifact_id: &str,
    created_at: &str,
    request: &Value,
) -> Result<(), RuntimeConversationArtifactControlCommandError> {
    let action_kind = string_field(request, "action_kind").unwrap_or_else(|| "update".to_string());
    if let Some(title) = string_field(request, "title") {
        set_string(artifact, "title", &title);
    }
    if let Some(state_label) = string_field(request, "state_label") {
        set_string(artifact, "state_label", &state_label);
    }
    let revision = revision(artifact_id, created_at, request);
    push_value(artifact, "revisions", revision.clone());
    set_string(
        artifact,
        "latest_revision_id",
        revision["revision_id"].as_str().unwrap_or(""),
    );
    set_string(artifact, "updated_at", created_at);
    let action = json!({
        "schema_version": "ioi.conversation_artifact_action.v1",
        "action_id": format!("action_{}", short_hash(&format!("{artifact_id}:{action_kind}:{created_at}"))),
        "artifact_id": artifact_id,
        "action_kind": action_kind,
        "created_at": created_at,
        "revision_id": revision["revision_id"],
    });
    push_value(artifact, "actions", action);
    Ok(())
}

fn revision(artifact_id: &str, created_at: &str, request: &Value) -> Value {
    let revision_id = format!(
        "revision_{}",
        short_hash(&format!(
            "{artifact_id}:{created_at}:{}",
            string_field(request, "idempotency_key").unwrap_or_default()
        ))
    );
    json!({
        "schema_version": CONVERSATION_ARTIFACT_REVISION_SCHEMA_VERSION,
        "revision_id": revision_id,
        "artifact_id": artifact_id,
        "created_at": created_at,
        "title": string_field(request, "title"),
        "body": string_field(request, "body").or_else(|| string_field(request, "content")),
        "source_refs": array_strings_field(request, "source_refs"),
        "original_refs": array_strings_field(request, "original_refs"),
        "projection_refs": array_strings_field(request, "projection_refs"),
        "preview_refs": array_strings_field(request, "preview_refs"),
        "log_refs": array_strings_field(request, "log_refs"),
        "rollback_refs": array_strings_field(request, "rollback_refs"),
    })
}

fn receipt_refs(
    request: &RuntimeConversationArtifactControlRequest,
    artifact_id: &str,
    operation_kind: &str,
) -> Vec<String> {
    let mut refs = string_vec(&request.receipt_refs);
    refs.extend(array_strings_field(&request.request, "receipt_refs"));
    if refs.is_empty() {
        refs.push(format!(
            "receipt_conversation_artifact_control_{}",
            short_hash(&format!("{artifact_id}:{operation_kind}"))
        ));
    }
    unique_strings(refs)
}

fn artifact_candidates(value: &Value) -> Vec<Value> {
    if let Some(records) = value.as_array() {
        return records.clone();
    }
    value
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn matches_artifact_id(record: &Value, artifact_id: &str) -> bool {
    record
        .get("id")
        .or_else(|| record.get("artifact_id"))
        .and_then(Value::as_str)
        .map(|value| value == artifact_id)
        .unwrap_or(false)
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn array_strings_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|value| optional_trimmed(Some(value)))
                .collect()
        })
        .unwrap_or_default()
}

fn string_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| optional_trimmed(Some(value)))
        .collect()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut result = Vec::new();
    for value in values {
        if !result.contains(&value) {
            result.push(value);
        }
    }
    result
}

fn set_string(value: &mut Value, key: &str, text: &str) {
    if let Value::Object(record) = value {
        record.insert(key.to_string(), Value::String(text.to_string()));
    }
}

fn set_array_strings(value: &mut Value, key: &str, values: &[String]) {
    if let Value::Object(record) = value {
        record.insert(
            key.to_string(),
            Value::Array(values.iter().cloned().map(Value::String).collect()),
        );
    }
}

fn push_unique_string(value: &mut Value, key: &str, text: String) {
    let mut values = value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !values
        .iter()
        .any(|value| value.as_str() == Some(text.as_str()))
    {
        values.push(Value::String(text));
    }
    if let Value::Object(record) = value {
        record.insert(key.to_string(), Value::Array(values));
    }
}

fn push_value(value: &mut Value, key: &str, item: Value) {
    let mut values = value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    values.push(item);
    if let Value::Object(record) = value {
        record.insert(key.to_string(), Value::Array(values));
    }
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request() -> RuntimeConversationArtifactControlRequest {
        RuntimeConversationArtifactControlRequest {
            schema_version: Some(
                RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation: Some("conversation_artifact_create".to_string()),
            operation_kind: Some("artifact.conversation.create".to_string()),
            thread_id: Some("thread-one".to_string()),
            request: json!({
                "title": "Draft",
                "body": "hello",
                "artifact_class": "document",
                "output_modality": "markdown",
                "created_at": "2026-06-12T00:00:00.000Z",
                "idempotency_key": "artifact-key"
            }),
            ..Default::default()
        }
    }

    #[test]
    fn rust_plans_conversation_artifact_create_record() {
        let record = RuntimeConversationArtifactControlCore
            .plan(&create_request())
            .expect("artifact create planned");

        assert_eq!(record.operation_kind, "artifact.conversation.create");
        assert_eq!(record.thread_id.as_deref(), Some("thread-one"));
        assert_eq!(record.artifact["thread_id"], "thread-one");
        assert_eq!(record.artifact["title"], "Draft");
        assert_eq!(record.artifact["revisions"][0]["body"], "hello");
        assert!(record
            .evidence_refs
            .contains(&"runtime_conversation_artifact_control_rust_owned".to_string()));
        assert!(!record.receipt_refs.is_empty());
    }

    #[test]
    fn rust_plans_conversation_artifact_action_export_and_promote() {
        let artifact = json!({
            "schema_version": CONVERSATION_ARTIFACT_SCHEMA_VERSION,
            "object": "ioi.conversation_artifact",
            "id": "artifact-one",
            "artifact_id": "artifact-one",
            "thread_id": "thread-one",
            "title": "Draft",
            "updated_at": "2026-06-12T00:00:00.000Z",
            "revisions": []
        });
        let base = RuntimeConversationArtifactControlRequest {
            artifact_id: Some("artifact-one".to_string()),
            artifact: artifact.clone(),
            request: json!({
                "created_at": "2026-06-12T00:05:00.000Z",
                "action_kind": "edit",
                "title": "Edited",
                "export_format": "zip",
                "promotion_target": "canvas"
            }),
            ..Default::default()
        };

        let action = RuntimeConversationArtifactControlCore
            .plan(&RuntimeConversationArtifactControlRequest {
                operation_kind: Some("artifact.conversation.action".to_string()),
                ..base.clone()
            })
            .expect("action planned");
        assert_eq!(action.artifact["title"], "Edited");
        assert_eq!(action.artifact["actions"][0]["action_kind"], "edit");

        let exported = RuntimeConversationArtifactControlCore
            .plan(&RuntimeConversationArtifactControlRequest {
                operation_kind: Some("artifact.conversation.export".to_string()),
                ..base.clone()
            })
            .expect("export planned");
        assert_eq!(exported.result["status"], "exported");
        assert!(exported.artifact["export_refs"].is_array());

        let promoted = RuntimeConversationArtifactControlCore
            .plan(&RuntimeConversationArtifactControlRequest {
                operation_kind: Some("artifact.conversation.promote".to_string()),
                ..base
            })
            .expect("promote planned");
        assert_eq!(promoted.result["status"], "promoted");
        assert!(promoted.artifact["promotion_refs"].is_array());
    }

    #[test]
    fn rust_shapes_conversation_artifact_control_command_response() {
        let response = plan_runtime_conversation_artifact_control_response(create_request())
            .expect("command response");
        assert_eq!(
            response["source"],
            "rust_runtime_conversation_artifact_control_command"
        );
        assert_eq!(
            response["record"]["schema_version"],
            RUNTIME_CONVERSATION_ARTIFACT_CONTROL_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            response["record"]["artifact"]["schema_version"],
            CONVERSATION_ARTIFACT_SCHEMA_VERSION
        );
    }

    #[test]
    fn rust_ignores_retired_conversation_artifact_request_aliases() {
        let mut request = create_request();
        request.request = json!({
            "threadId": "thread-retired",
            "artifactId": "artifact-retired",
            "createdAt": "2026-06-12T00:00:00.000Z",
            "idempotencyKey": "retired",
            "title": "Canonical",
            "created_at": "2026-06-12T00:00:00.000Z",
            "idempotency_key": "canonical"
        });
        let record = RuntimeConversationArtifactControlCore
            .plan(&request)
            .expect("aliases ignored");
        assert_eq!(record.artifact["thread_id"], "thread-one");
        assert_eq!(record.artifact["title"], "Canonical");
        assert_ne!(record.artifact_id, "artifact-retired");
    }

    #[test]
    fn rust_rejects_invalid_conversation_artifact_control_schema() {
        let mut request = create_request();
        request.schema_version = Some("legacy.conversation-artifact-control".to_string());
        let error = RuntimeConversationArtifactControlCore
            .plan(&request)
            .expect_err("invalid schema must fail");
        assert_eq!(
            error.code(),
            "runtime_conversation_artifact_control_schema_version_invalid"
        );
    }

    #[test]
    fn rust_rejects_missing_conversation_artifact_action_candidate() {
        let error = RuntimeConversationArtifactControlCore
            .plan(&RuntimeConversationArtifactControlRequest {
                operation_kind: Some("artifact.conversation.action".to_string()),
                artifact_id: Some("artifact-missing".to_string()),
                ..Default::default()
            })
            .expect_err("missing artifact must fail");
        assert_eq!(
            error.code(),
            "runtime_conversation_artifact_control_artifact_not_found"
        );
    }
}
