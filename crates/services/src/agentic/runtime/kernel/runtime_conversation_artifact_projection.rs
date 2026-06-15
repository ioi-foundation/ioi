use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::{Component, Path},
};

pub const RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.conversation-artifact-projection-request.v1";
pub const RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.conversation_artifact_projection.v1";
const CONVERSATION_ARTIFACT_SCHEMA_VERSION: &str = "ioi.conversation_artifact.v1";

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
    pub state_dir: Option<String>,
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

impl RuntimeConversationArtifactProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeConversationArtifactProjectionRequest,
    ) -> Result<
        RuntimeConversationArtifactProjectionRecord,
        RuntimeConversationArtifactProjectionCommandError,
    > {
        let projection_kind = normalized_projection_kind(request)?;
        reject_projection_candidate_transport(request)?;
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
            .unwrap_or_else(|| "runtime.conversation_artifact_projection.rust_api".to_string());
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

fn projection_for_kind(
    projection_kind: &str,
    request: &RuntimeConversationArtifactProjectionRequest,
) -> Result<Value, RuntimeConversationArtifactProjectionCommandError> {
    let mut artifacts = conversation_artifacts_from_state_dir(request)?;
    match projection_kind {
        "list" => {
            let mut records: Vec<Value> = artifacts
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
            Ok(artifacts
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
            let revisions = artifacts
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

fn reject_projection_candidate_transport(
    request: &RuntimeConversationArtifactProjectionRequest,
) -> Result<(), RuntimeConversationArtifactProjectionCommandError> {
    let has_candidate_projection = match &request.projection {
        Value::Null => false,
        Value::Object(object) => !object.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => true,
    };
    if has_candidate_projection {
        return Err(RuntimeConversationArtifactProjectionCommandError::new(
            "runtime_conversation_artifact_projection_candidate_transport_retired",
            "conversation artifact projection rejects JS-supplied artifact candidates; provide state_dir for Agentgres replay",
        ));
    }
    Ok(())
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

fn conversation_artifacts_from_state_dir(
    request: &RuntimeConversationArtifactProjectionRequest,
) -> Result<std::vec::IntoIter<Value>, RuntimeConversationArtifactProjectionCommandError> {
    let state_dir = optional_trimmed(request.state_dir.as_deref()).ok_or_else(|| {
        RuntimeConversationArtifactProjectionCommandError::new(
            "runtime_conversation_artifact_projection_state_dir_required",
            "conversation artifact projection requires runtime state_dir for Agentgres artifact replay",
        )
    })?;
    let state_root = Path::new(&state_dir);
    let records = load_conversation_artifact_records(state_root)?
        .into_iter()
        .filter(canonical_conversation_artifact)
        .filter(active_conversation_artifact)
        .map(|record| conversation_artifact_with_inline_preview(record, state_root))
        .collect::<Vec<_>>();
    Ok(records.into_iter())
}

fn load_conversation_artifact_records(
    state_root: &Path,
) -> Result<Vec<Value>, RuntimeConversationArtifactProjectionCommandError> {
    let dir = state_root.join("artifacts");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&dir).map_err(|error| {
        RuntimeConversationArtifactProjectionCommandError::new(
            "runtime_conversation_artifact_projection_replay_read_failed",
            format!("conversation artifact projection could not read Agentgres artifacts: {error}"),
        )
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            RuntimeConversationArtifactProjectionCommandError::new(
                "runtime_conversation_artifact_projection_replay_read_failed",
                format!(
                    "conversation artifact projection could not inspect Agentgres artifact entry: {error}"
                ),
            )
        })?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut records = Vec::new();
    for path in paths.into_iter().take(1000) {
        let contents = fs::read_to_string(&path).map_err(|error| {
            RuntimeConversationArtifactProjectionCommandError::new(
                "runtime_conversation_artifact_projection_replay_read_failed",
                format!(
                    "conversation artifact projection could not read Agentgres artifact record {}: {error}",
                    path.display()
                ),
            )
        })?;
        let record = serde_json::from_str(&contents).map_err(|error| {
            RuntimeConversationArtifactProjectionCommandError::new(
                "runtime_conversation_artifact_projection_replay_record_invalid",
                format!(
                    "conversation artifact projection found invalid Agentgres artifact record {}: {error}",
                    path.display()
                ),
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

fn canonical_conversation_artifact(record: &Value) -> bool {
    record.as_object().is_some()
        && json_string(record, "schema_version").as_deref()
            == Some(CONVERSATION_ARTIFACT_SCHEMA_VERSION)
        && json_string(record, "object").as_deref() == Some("ioi.conversation_artifact")
        && (json_string(record, "id").is_some() || json_string(record, "artifact_id").is_some())
}

fn active_conversation_artifact(record: &Value) -> bool {
    json_string(record, "status").as_deref() != Some("deleted")
        && json_string(record, "deleted_at").is_none()
}

fn conversation_artifact_with_inline_preview(mut record: Value, state_root: &Path) -> Value {
    let Some(preview) = safe_inline_preview(&record, state_root) else {
        return record;
    };
    if let Some(object) = record.as_object_mut() {
        object.insert("preview_inline".to_string(), preview);
    }
    record
}

fn safe_inline_preview(record: &Value, state_root: &Path) -> Option<Value> {
    let preview_ref = record
        .get("preview_refs")?
        .as_array()?
        .first()?
        .as_object()?;
    let relative_path = preview_ref.get("path")?.as_str()?.trim();
    let media_type = preview_ref.get("media_type")?.as_str()?.trim();
    if relative_path.is_empty() || !inline_preview_media_type_allowed(media_type) {
        return None;
    }
    let relative = Path::new(relative_path);
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return None;
    }
    let root = state_root.join("conversation-artifacts");
    let root = fs::canonicalize(&root).ok()?;
    let resolved = fs::canonicalize(root.join(relative)).ok()?;
    if !resolved.starts_with(&root) {
        return None;
    }
    let metadata = fs::metadata(&resolved).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let max_bytes = 128 * 1024usize;
    let mut file = fs::File::open(&resolved).ok()?;
    let mut buffer = Vec::new();
    file.by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buffer)
        .ok()?;
    let truncated = buffer.len() > max_bytes || metadata.len() > max_bytes as u64;
    if buffer.len() > max_bytes {
        buffer.truncate(max_bytes);
    }
    Some(json!({
        "media_type": media_type,
        "text": String::from_utf8_lossy(&buffer).to_string(),
        "truncated": truncated,
        "source_ref": preview_ref.get("ref").and_then(Value::as_str),
    }))
}

fn inline_preview_media_type_allowed(media_type: &str) -> bool {
    let media_type = media_type.to_ascii_lowercase();
    [
        "text/html",
        "text/markdown",
        "text/csv",
        "application/json",
        "text/x-diff",
        "text/plain",
    ]
    .iter()
    .any(|prefix| media_type.starts_with(prefix))
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
    json_string(record, "updated_at").unwrap_or_default()
}

fn json_string(record: &Value, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_i64().map(|number| number.to_string()))
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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
    use std::{fs, path::Path};

    fn base_request(
        projection_kind: &str,
        state_dir: &Path,
    ) -> RuntimeConversationArtifactProjectionRequest {
        RuntimeConversationArtifactProjectionRequest {
            projection_kind: Some(projection_kind.to_string()),
            thread_id: Some("thread-one".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            ..Default::default()
        }
    }

    fn write_artifact_record(state_dir: &Path, file_name: &str, record: Value) {
        let artifact_dir = state_dir.join("artifacts");
        fs::create_dir_all(&artifact_dir).expect("artifact dir");
        fs::write(
            artifact_dir.join(file_name),
            serde_json::to_string_pretty(&record).expect("artifact json"),
        )
        .expect("write artifact record");
    }

    fn seed_artifact_state(state_dir: &Path) {
        write_artifact_record(
            state_dir,
            "artifact-old.json",
            json!({
                "schema_version": CONVERSATION_ARTIFACT_SCHEMA_VERSION,
                "object": "ioi.conversation_artifact",
                "id": "artifact-old",
                "artifact_id": "artifact-old",
                "thread_id": "thread-one",
                "title": "Old",
                "status": "active",
                "updated_at": "2026-06-08T00:00:00.000Z",
                "revisions": [{ "revision_id": "rev-old" }],
                "receipt_refs": ["receipt-old"]
            }),
        );
        write_artifact_record(
            state_dir,
            "artifact-other.json",
            json!({
                "schema_version": CONVERSATION_ARTIFACT_SCHEMA_VERSION,
                "object": "ioi.conversation_artifact",
                "id": "artifact-other",
                "artifact_id": "artifact-other",
                "thread_id": "thread-two",
                "title": "Other",
                "status": "active",
                "updated_at": "2026-06-08T00:02:00.000Z",
                "revisions": [{ "revision_id": "rev-other" }],
                "receipt_refs": ["receipt-other"]
            }),
        );
        write_artifact_record(
            state_dir,
            "artifact-new.json",
            json!({
                "schema_version": CONVERSATION_ARTIFACT_SCHEMA_VERSION,
                "object": "ioi.conversation_artifact",
                "id": "artifact-new",
                "artifact_id": "artifact-new",
                "thread_id": "thread-one",
                "title": "New",
                "status": "active",
                "updated_at": "2026-06-08T00:01:00.000Z",
                "revisions": [{ "revision_id": "rev-new" }],
                "receipt_refs": ["receipt-new"]
            }),
        );
        write_artifact_record(
            state_dir,
            "artifact-deleted.json",
            json!({
                "schema_version": CONVERSATION_ARTIFACT_SCHEMA_VERSION,
                "object": "ioi.conversation_artifact",
                "id": "artifact-deleted",
                "artifact_id": "artifact-deleted",
                "thread_id": "thread-one",
                "title": "Deleted",
                "status": "deleted",
                "deleted_at": "2026-06-08T00:03:00.000Z",
                "updated_at": "2026-06-08T00:03:00.000Z",
                "revisions": [{ "revision_id": "rev-deleted" }]
            }),
        );
        write_artifact_record(
            state_dir,
            "artifact-js-authored.json",
            json!({
                "schemaVersion": CONVERSATION_ARTIFACT_SCHEMA_VERSION,
                "object": "ioi.conversation_artifact",
                "id": "artifact-js-authored",
                "threadId": "thread-one",
                "title": "Retired JS candidate"
            }),
        );
    }

    #[test]
    fn rust_projects_conversation_artifact_list_get_and_revisions() {
        let temp = tempfile::tempdir().expect("tempdir");
        seed_artifact_state(temp.path());
        let request = base_request("list", temp.path());

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
                state_dir: Some(temp.path().to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect("get projection");
        assert_eq!(get.record_count, 1);
        assert_eq!(get.projection["title"], "Old");

        let revisions = RuntimeConversationArtifactProjectionCore
            .project(&RuntimeConversationArtifactProjectionRequest {
                projection_kind: Some("revisions".to_string()),
                artifact_id: Some("artifact-new".to_string()),
                state_dir: Some(temp.path().to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect("revision projection");
        assert_eq!(revisions.record_count, 1);
        assert_eq!(revisions.projection[0]["revision_id"], "rev-new");
    }

    #[test]
    fn rust_rejects_conversation_artifact_projection_candidate_transport() {
        let temp = tempfile::tempdir().expect("tempdir");
        seed_artifact_state(temp.path());
        let mut request = base_request("list", temp.path());
        request.projection = json!({"artifacts": [{"id": "artifact-js-candidate"}]});

        let error = RuntimeConversationArtifactProjectionCore
            .project(&request)
            .expect_err("candidate projection rejected");
        assert_eq!(
            error.code(),
            "runtime_conversation_artifact_projection_candidate_transport_retired"
        );
    }

    #[test]
    fn rust_requires_state_dir_for_conversation_artifact_projection() {
        let error = RuntimeConversationArtifactProjectionCore
            .project(&RuntimeConversationArtifactProjectionRequest {
                projection_kind: Some("list".to_string()),
                ..Default::default()
            })
            .expect_err("missing state_dir rejected");
        assert_eq!(
            error.code(),
            "runtime_conversation_artifact_projection_state_dir_required"
        );
    }

    #[test]
    fn rust_rejects_unknown_conversation_artifact_projection_kind() {
        let error = RuntimeConversationArtifactProjectionCore
            .project(&RuntimeConversationArtifactProjectionRequest {
                projection_kind: Some("legacy".to_string()),
                state_dir: Some("/runtime-state".to_string()),
                ..Default::default()
            })
            .expect_err("unsupported projection kind must fail");

        assert_eq!(
            error.code(),
            "runtime_conversation_artifact_projection_kind_invalid"
        );
    }
}
