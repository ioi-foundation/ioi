use std::{fs, path::Path};

use serde_json::Value;

use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn conversation_states(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(agentgres_conversation_state_records(request)?))
}

pub(super) fn conversation_state_records(request: &ModelMountReadProjectionRequest) -> Vec<Value> {
    agentgres_conversation_state_records(request).unwrap_or_default()
}

fn agentgres_conversation_state_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_conversation_replay_state_dir_required",
                "model conversation projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("model-conversations");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_conversation_replay_read_failed",
            format!("failed to read model conversation records: {error}"),
        )
    })?;
    let mut records = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .map(|path| {
            fs::read_to_string(&path)
                .map_err(|error| {
                    ModelMountReadProjectionError::new(
                        "model_mount_conversation_replay_read_failed",
                        format!(
                            "failed to read model conversation record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_conversation_replay_invalid_record",
                            format!(
                                "failed to decode model conversation record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_conversation_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(right, "created_at")
            .cmp(&string_field(left, "created_at"))
            .then_with(|| string_field(right, "id").cmp(&string_field(left, "id")))
    });
    Ok(records)
}

fn admitted_conversation_record(record: Value) -> Option<Value> {
    if string_field(&record, "object") != "ioi.model_mount_conversation_state" {
        return None;
    }
    if string_field(&record, "rust_core_boundary") != "model_mount.conversation" {
        return None;
    }
    if string_field(&record, "conversation_hash").is_empty() {
        return None;
    }
    let evidence_refs = evidence_refs(&record);
    if !evidence_refs.iter().any(|value| {
        value == "model_mount_conversation_state_rust_owned"
            || value == "model_mount_stream_completion_rust_owned"
    }) {
        return None;
    }
    if !evidence_refs
        .iter()
        .any(|value| value == "agentgres_model_conversation_truth_required")
    {
        return None;
    }
    Some(record)
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn evidence_refs(value: &Value) -> Vec<String> {
    value
        .get("evidence_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;
    use serde_json::json;

    use super::super::MODEL_MOUNT_CONVERSATION_PROJECTION_KIND;

    fn request(state_dir: Option<String>) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: MODEL_MOUNT_CONVERSATION_PROJECTION_KIND.to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir,
            state: json!({}),
        }
    }

    #[test]
    fn conversation_projection_replays_agentgres_records_and_sorts_newest_first() {
        let temp = tempfile::tempdir().expect("tempdir");
        let conversation_dir = temp.path().join("model-conversations");
        fs::create_dir_all(&conversation_dir).expect("conversation dir");
        for record in [
            json!({
                "id": "legacy-js-record",
                "object": "ioi.model_mount_conversation_state",
                "created_at": "2026-06-13T00:00:03.000Z"
            }),
            json!({
                "id": "resp-state",
                "object": "ioi.model_mount_conversation_state",
                "created_at": "2026-06-13T00:00:01.000Z",
                "rust_core_boundary": "model_mount.conversation",
                "conversation_hash": "sha256:conversation-state",
                "evidence_refs": [
                    "model_mount_conversation_state_rust_owned",
                    "agentgres_model_conversation_truth_required"
                ]
            }),
            json!({
                "id": "resp-stream",
                "object": "ioi.model_mount_conversation_state",
                "created_at": "2026-06-13T00:00:02.000Z",
                "rust_core_boundary": "model_mount.conversation",
                "conversation_hash": "sha256:conversation-stream",
                "evidence_refs": [
                    "model_mount_stream_completion_rust_owned",
                    "agentgres_model_conversation_truth_required"
                ]
            }),
        ] {
            fs::write(
                conversation_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write conversation record");
        }

        let projection =
            conversation_states(&request(Some(temp.path().to_string_lossy().to_string())))
                .expect("conversation projection");

        let records = projection.as_array().expect("conversation records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["id"], "resp-stream");
        assert_eq!(records[1]["id"], "resp-state");
        assert!(records
            .iter()
            .all(|record| record["id"] != "legacy-js-record"));
    }

    #[test]
    fn conversation_projection_fails_closed_without_agentgres_state_dir() {
        let error = conversation_states(&request(None)).expect_err("state dir required");
        assert_eq!(
            error.code,
            "model_mount_conversation_replay_state_dir_required"
        );
    }
}
