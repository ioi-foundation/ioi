use serde::Deserialize;
use serde_json::{json, Value};

pub const RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.conversation-artifact-projection-request.v1";
pub const RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.conversation_artifact_projection.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeConversationArtifactProjectionRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub projection: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConversationArtifactProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeConversationArtifactProjectionCommandError {
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
pub struct RuntimeConversationArtifactProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeConversationArtifactProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub thread_id: Option<String>,
    pub artifact_id: Option<String>,
    pub source: String,
    pub projection: Value,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

pub fn project_runtime_conversation_artifact_projection_response(
    request: RuntimeConversationArtifactProjectionRequest,
) -> Result<Value, RuntimeConversationArtifactProjectionCommandError> {
    let record = RuntimeConversationArtifactProjectionCore::default().project(&request)?;
    Ok(json!({
        "source": "rust_runtime_conversation_artifact_projection_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeConversationArtifactProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeConversationArtifactProjectionRequest,
    ) -> Result<
        RuntimeConversationArtifactProjectionRecord,
        RuntimeConversationArtifactProjectionCommandError,
    > {
        let projection_kind = normalized_projection_kind(request)?;
        let projection = projection_for_kind(&projection_kind, request)?;
        let record_count = record_count_for_projection(&projection);
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "runtime_conversation_artifact_projection".to_string());
        let operation_kind = request.operation_kind.clone().unwrap_or_else(|| {
            format!("runtime.conversation_artifact_projection.{projection_kind}")
        });
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "runtime.conversation_artifact_projection.rust_command".to_string());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_conversation_artifact_read_projection_rust_owned".to_string(),
                "agentgres_conversation_artifact_projection_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };

        Ok(RuntimeConversationArtifactProjectionRecord {
            operation,
            operation_kind,
            projection_kind: projection_kind.clone(),
            thread_id: optional_trimmed(request.thread_id.as_deref()),
            artifact_id: optional_trimmed(request.artifact_id.as_deref()),
            source,
            projection,
            record_count,
            evidence_refs,
            receipt_refs: vec![format!(
                "receipt_runtime_conversation_artifact_projection_{projection_kind}"
            )],
        })
    }
}

impl RuntimeConversationArtifactProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_conversation_artifact_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "thread_id": self.thread_id,
            "artifact_id": self.artifact_id,
            "source": self.source,
            "projection": self.projection,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

fn projection_for_kind(
    projection_kind: &str,
    request: &RuntimeConversationArtifactProjectionRequest,
) -> Result<Value, RuntimeConversationArtifactProjectionCommandError> {
    match projection_kind {
        "list" => {
            let mut records: Vec<Value> = artifact_candidates(&request.projection)
                .into_iter()
                .filter(|record| matches_thread(record, request.thread_id.as_deref()))
                .collect();
            records.sort_by(|left, right| updated_at(right).cmp(&updated_at(left)));
            Ok(Value::Array(records))
        }
        "get" => {
            let artifact_id =
                optional_trimmed(request.artifact_id.as_deref()).ok_or_else(|| {
                    RuntimeConversationArtifactProjectionCommandError::new(
                        "runtime_conversation_artifact_projection_artifact_id_required",
                        "conversation artifact get projection requires artifact_id",
                    )
                })?;
            Ok(artifact_candidates(&request.projection)
                .into_iter()
                .find(|record| matches_artifact_id(record, &artifact_id))
                .unwrap_or(Value::Null))
        }
        "revisions" => {
            let artifact_id =
                optional_trimmed(request.artifact_id.as_deref()).ok_or_else(|| {
                    RuntimeConversationArtifactProjectionCommandError::new(
                        "runtime_conversation_artifact_projection_artifact_id_required",
                        "conversation artifact revision projection requires artifact_id",
                    )
                })?;
            let revisions = artifact_candidates(&request.projection)
                .into_iter()
                .find(|record| matches_artifact_id(record, &artifact_id))
                .and_then(|record| record.get("revisions").cloned())
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default();
            Ok(Value::Array(revisions))
        }
        _ => Err(RuntimeConversationArtifactProjectionCommandError::new(
            "runtime_conversation_artifact_projection_kind_invalid",
            format!("unsupported conversation artifact projection kind {projection_kind}"),
        )),
    }
}

fn normalized_projection_kind(
    request: &RuntimeConversationArtifactProjectionRequest,
) -> Result<String, RuntimeConversationArtifactProjectionCommandError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    if let Some(last) = operation_kind.split('.').next_back() {
        if !last.is_empty() {
            return Ok(last.to_string());
        }
    }
    Err(RuntimeConversationArtifactProjectionCommandError::new(
        "runtime_conversation_artifact_projection_kind_required",
        "conversation artifact projection kind is required",
    ))
}

fn artifact_candidates(projection: &Value) -> Vec<Value> {
    if let Some(records) = projection.as_array() {
        return records.clone();
    }
    projection
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn matches_thread(record: &Value, thread_id: Option<&str>) -> bool {
    let Some(thread_id) = optional_trimmed(thread_id) else {
        return true;
    };
    record
        .get("thread_id")
        .and_then(Value::as_str)
        .map(|value| value == thread_id)
        .unwrap_or(false)
}

fn matches_artifact_id(record: &Value, artifact_id: &str) -> bool {
    record
        .get("id")
        .or_else(|| record.get("artifact_id"))
        .and_then(Value::as_str)
        .map(|value| value == artifact_id)
        .unwrap_or(false)
}

fn updated_at(record: &Value) -> String {
    record
        .get("updated_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn record_count_for_projection(projection: &Value) -> usize {
    match projection {
        Value::Array(values) => values.len(),
        Value::Null => 0,
        Value::Object(_) => 1,
        _ => 0,
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_trimmed_lower(value: Option<&str>) -> Option<String> {
    optional_trimmed(value).map(|value| value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_projects_conversation_artifact_list_get_and_revisions() {
        let request = RuntimeConversationArtifactProjectionRequest {
            projection_kind: Some("list".to_string()),
            thread_id: Some("thread-one".to_string()),
            projection: json!({
                "artifacts": [
                    {
                        "id": "artifact-old",
                        "thread_id": "thread-one",
                        "title": "Old",
                        "updated_at": "2026-06-08T00:00:00.000Z",
                        "revisions": [{ "revision_id": "rev-old" }]
                    },
                    {
                        "id": "artifact-other",
                        "thread_id": "thread-two",
                        "title": "Other",
                        "updated_at": "2026-06-08T00:02:00.000Z",
                        "revisions": [{ "revision_id": "rev-other" }]
                    },
                    {
                        "id": "artifact-new",
                        "thread_id": "thread-one",
                        "title": "New",
                        "updated_at": "2026-06-08T00:01:00.000Z",
                        "revisions": [{ "revision_id": "rev-new" }]
                    }
                ]
            }),
            ..Default::default()
        };

        let list = RuntimeConversationArtifactProjectionCore
            .project(&request)
            .expect("list projection");
        assert_eq!(list.projection_kind, "list");
        assert_eq!(list.record_count, 2);
        assert_eq!(list.projection[0]["id"], "artifact-new");
        assert_eq!(list.projection[1]["id"], "artifact-old");

        let get = RuntimeConversationArtifactProjectionCore
            .project(&RuntimeConversationArtifactProjectionRequest {
                projection_kind: Some("get".to_string()),
                artifact_id: Some("artifact-old".to_string()),
                projection: request.projection.clone(),
                ..Default::default()
            })
            .expect("get projection");
        assert_eq!(get.record_count, 1);
        assert_eq!(get.projection["title"], "Old");

        let revisions = RuntimeConversationArtifactProjectionCore
            .project(&RuntimeConversationArtifactProjectionRequest {
                projection_kind: Some("revisions".to_string()),
                artifact_id: Some("artifact-new".to_string()),
                projection: request.projection,
                ..Default::default()
            })
            .expect("revision projection");
        assert_eq!(revisions.record_count, 1);
        assert_eq!(revisions.projection[0]["revision_id"], "rev-new");
    }

    #[test]
    fn rust_shapes_conversation_artifact_projection_command_response() {
        let response = project_runtime_conversation_artifact_projection_response(
            RuntimeConversationArtifactProjectionRequest {
                operation_kind: Some("runtime.conversation_artifact_projection.get".to_string()),
                projection_kind: Some("get".to_string()),
                artifact_id: Some("artifact-one".to_string()),
                projection: json!({
                    "artifacts": [{
                        "id": "artifact-one",
                        "thread_id": "thread-one",
                        "title": "One",
                        "updated_at": "2026-06-08T00:00:00.000Z"
                    }]
                }),
                ..Default::default()
            },
        )
        .expect("command response");

        assert_eq!(
            response["source"],
            "rust_runtime_conversation_artifact_projection_command"
        );
        assert_eq!(
            response["record"]["schema_version"],
            RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(response["record"]["projection_kind"], "get");
        assert_eq!(response["record"]["projection"]["id"], "artifact-one");
        assert_eq!(response["record"]["record_count"], 1);
    }

    #[test]
    fn rust_rejects_unknown_conversation_artifact_projection_kind() {
        let error = RuntimeConversationArtifactProjectionCore
            .project(&RuntimeConversationArtifactProjectionRequest {
                projection_kind: Some("legacy".to_string()),
                ..Default::default()
            })
            .expect_err("unsupported projection kind must fail");

        assert_eq!(
            error.code(),
            "runtime_conversation_artifact_projection_kind_invalid"
        );
    }
}
