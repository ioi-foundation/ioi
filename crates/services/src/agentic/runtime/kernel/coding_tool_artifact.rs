use serde_json::{json, Value};

pub const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
const CODING_TOOL_DATA_PLANE_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-data-plane.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingToolArtifactError {
    code: &'static str,
    message: String,
}

impl CodingToolArtifactError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingToolArtifactObservation {
    pub observation: Value,
    pub artifact_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub evidence_ref: String,
}

pub fn normalize_artifact_read(
    input: &Value,
) -> Result<CodingToolArtifactObservation, CodingToolArtifactError> {
    normalize_prefetched_artifact_result(
        "artifact.read",
        input,
        "rust_artifact_read",
        &["artifact_id", "artifact_ref"],
    )
}

pub fn normalize_tool_retrieve_result(
    input: &Value,
) -> Result<CodingToolArtifactObservation, CodingToolArtifactError> {
    normalize_prefetched_artifact_result(
        "tool.retrieve_result",
        input,
        "rust_tool_result_retrieve",
        &["tool_call_id", "artifact_id"],
    )
}

fn normalize_prefetched_artifact_result(
    tool_id: &str,
    input: &Value,
    backend: &str,
    evidence_keys: &[&str],
) -> Result<CodingToolArtifactObservation, CodingToolArtifactError> {
    if input.get("rustWorkloadDataPlane").is_some() {
        return Err(CodingToolArtifactError::new(
            "data_plane_payload_alias_retired",
            format!("{tool_id} requires canonical rust_workload_data_plane"),
        ));
    }
    let envelope = input
        .get("rust_workload_data_plane")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_payload_required",
                format!("{tool_id} requires a daemon-provided data-plane payload"),
            )
        })?;
    if envelope.get("schemaVersion").is_some() {
        return Err(CodingToolArtifactError::new(
            "data_plane_schema_alias_retired",
            format!("{tool_id} requires canonical data-plane schema_version"),
        ));
    }
    let schema_version = envelope
        .get("schema_version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_schema_version_required",
                format!("{tool_id} requires a data-plane schema_version"),
            )
        })?;
    if schema_version != CODING_TOOL_DATA_PLANE_SCHEMA_VERSION {
        return Err(CodingToolArtifactError::new(
            "data_plane_schema_version_unsupported",
            format!("{tool_id} does not accept data-plane schema {schema_version}"),
        ));
    }
    let source = envelope
        .get("source")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_source_required",
                format!("{tool_id} requires a data-plane source"),
            )
        })?;
    if source != "daemon_artifact_store" {
        return Err(CodingToolArtifactError::new(
            "data_plane_source_unsupported",
            format!("{tool_id} does not accept data-plane source {source}"),
        ));
    }
    let operation = envelope
        .get("operation")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_operation_required",
                format!("{tool_id} requires a data-plane operation"),
            )
        })?;
    if operation != tool_id {
        return Err(CodingToolArtifactError::new(
            "data_plane_operation_mismatch",
            format!("{tool_id} received data-plane operation {operation}"),
        ));
    }
    let mut normalized = envelope.get("result").cloned().ok_or_else(|| {
        CodingToolArtifactError::new(
            "data_plane_result_required",
            format!("{tool_id} requires a data-plane result"),
        )
    })?;
    let fallback_artifact_ref = optional_json_string(&normalized, &["artifact_id", "artifact_ref"]);
    let object = normalized.as_object_mut().ok_or_else(|| {
        CodingToolArtifactError::new(
            "data_plane_result_invalid",
            format!("{tool_id} data-plane result must be an object"),
        )
    })?;
    let content = object
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_content_required",
                format!("{tool_id} data-plane result must include content"),
            )
        })?
        .to_string();
    let content_hash = sha256_hex(content.as_bytes())?;

    remove_retired_result_aliases(object);
    object.insert(
        "schema_version".to_string(),
        json!(CODING_TOOL_RESULT_SCHEMA_VERSION),
    );
    object.insert("backend".to_string(), json!(backend));
    object.insert("data_plane_source".to_string(), json!(source));
    object.insert("rust_workload_data_plane".to_string(), json!(true));
    object.insert("content_hash".to_string(), json!(content_hash));
    object.insert("shell_fallback_used".to_string(), json!(false));
    if !object.contains_key("artifact_refs") {
        if let Some(artifact_id) = fallback_artifact_ref {
            object.insert("artifact_refs".to_string(), json!([artifact_id]));
        }
    }

    let artifact_refs = json_string_refs(&normalized, &["artifact_refs"]);
    let receipt_refs = json_string_refs(&normalized, &["receipt_refs"]);
    let evidence_ref = optional_json_string(&normalized, evidence_keys)
        .map(|value| safe_ref_path(&value))
        .unwrap_or_else(|| "unknown".to_string());

    Ok(CodingToolArtifactObservation {
        observation: normalized,
        artifact_refs,
        receipt_refs,
        evidence_ref,
    })
}

fn remove_retired_result_aliases(object: &mut serde_json::Map<String, Value>) {
    for key in [
        "schemaVersion",
        "dataPlaneSource",
        "rustWorkloadDataPlane",
        "contentHash",
        "shellFallbackUsed",
        "artifactRefs",
        "receiptRefs",
    ] {
        object.remove(key);
    }
}

fn json_string_refs(value: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        let refs = sanitize_string_array(value.get(*key));
        if !refs.is_empty() {
            return refs;
        }
    }
    Vec::new()
}

fn sanitize_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .take(100)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn optional_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn safe_ref_path(value: &str) -> String {
    let safe = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect::<String>();
    if safe.is_empty() {
        "artifact".to_string()
    } else {
        safe
    }
}

fn sha256_hex(bytes: &[u8]) -> Result<String, CodingToolArtifactError> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| CodingToolArtifactError::new("sha256_failed", error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn artifact_read_requires_canonical_data_plane_and_emits_canonical_result() {
        let normalized = normalize_artifact_read(&json!({
            "artifact_id": "artifact_alpha",
            "rust_workload_data_plane": {
                "schema_version": "ioi.runtime.coding-tool-data-plane.v1",
                "source": "daemon_artifact_store",
                "operation": "artifact.read",
                "result": {
                    "schemaVersion": "retired",
                    "artifact_id": "artifact_alpha",
                    "artifact_ref": "artifact_alpha",
                    "artifact_refs": ["artifact_alpha"],
                    "artifactRefs": ["retired_artifact"],
                    "content": "hello artifact\n",
                    "contentHash": "prefetch-hash",
                    "receipt_refs": ["receipt_artifact_prefetch"],
                    "receiptRefs": ["receipt_retired"],
                    "shellFallbackUsed": true
                }
            }
        }))
        .expect("canonical artifact data plane");

        assert_eq!(normalized.artifact_refs, vec!["artifact_alpha"]);
        assert_eq!(normalized.receipt_refs, vec!["receipt_artifact_prefetch"]);
        assert_eq!(normalized.evidence_ref, "artifact_alpha");
        assert_eq!(
            normalized.observation["schema_version"],
            CODING_TOOL_RESULT_SCHEMA_VERSION
        );
        assert_eq!(normalized.observation["backend"], "rust_artifact_read");
        assert_eq!(
            normalized.observation["data_plane_source"],
            "daemon_artifact_store"
        );
        assert_eq!(normalized.observation["shell_fallback_used"], false);
        assert_eq!(
            normalized.observation["content_hash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        for key in [
            "schemaVersion",
            "artifactRefs",
            "contentHash",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert!(normalized.observation.get(key).is_none());
        }
    }

    #[test]
    fn tool_retrieve_result_rejects_retired_data_plane_alias() {
        let error = normalize_tool_retrieve_result(&json!({
            "tool_call_id": "tool_patch",
            "rustWorkloadDataPlane": {
                "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1"
            }
        }))
        .expect_err("retired envelope alias should fail");

        assert_eq!(error.code(), "data_plane_payload_alias_retired");
    }

    #[test]
    fn artifact_read_rejects_retired_schema_alias() {
        let error = normalize_artifact_read(&json!({
            "artifact_id": "artifact_alpha",
            "rust_workload_data_plane": {
                "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1",
                "source": "daemon_artifact_store",
                "operation": "artifact.read",
                "result": {
                    "artifact_id": "artifact_alpha",
                    "content": "hello"
                }
            }
        }))
        .expect_err("retired schema alias should fail");

        assert_eq!(error.code(), "data_plane_schema_alias_retired");
    }
}
