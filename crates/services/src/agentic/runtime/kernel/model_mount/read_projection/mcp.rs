use serde_json::{json, Value};
use std::fs;
use std::path::Path;

use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn mcp_servers(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let mut servers = agentgres_mcp_servers(request)?;
    servers.sort_by(|left, right| {
        string_field(left, "id")
            .cmp(&string_field(right, "id"))
            .then_with(|| string_field(left, "label").cmp(&string_field(right, "label")))
    });
    Ok(Value::Array(servers))
}

fn agentgres_mcp_servers(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_mcp_projection_state_dir_required",
                "MCP server projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("mcp-servers");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_mcp_projection_read_failed",
            format!("failed to read MCP server records: {error}"),
        )
    })?;
    let records = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .map(|path| {
            fs::read_to_string(&path)
                .map_err(|error| {
                    ModelMountReadProjectionError::new(
                        "model_mount_mcp_projection_read_failed",
                        format!(
                            "failed to read MCP server record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_mcp_projection_invalid_record",
                            format!(
                                "failed to decode MCP server record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(records
        .into_iter()
        .flat_map(rust_authored_mcp_servers)
        .collect())
}

fn rust_authored_mcp_servers(record: Value) -> Vec<Value> {
    let Some(object) = record.as_object() else {
        return vec![];
    };
    if string_field(&record, "object").as_deref() != Some("ioi.model_mount_mcp_workflow") {
        return vec![];
    }
    if string_field(&record, "rust_core_boundary").as_deref() != Some("model_mount.mcp_workflow") {
        return vec![];
    }
    if string_field(&record, "operation_kind").as_deref() != Some("model_mount.mcp_server.import")
        && string_field(&record, "operation_kind").as_deref()
            != Some("model_mount.mcp_server.ephemeral_register")
    {
        return vec![];
    }
    object
        .get("details")
        .and_then(Value::as_object)
        .and_then(|details| details.get("servers"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(public_mcp_server)
        .collect()
}

fn public_mcp_server(server: Value) -> Option<Value> {
    let id = string_field(&server, "id")?;
    let label = string_field(&server, "label").unwrap_or_else(|| id.clone());
    Some(json!({
        "id": id,
        "label": label,
        "transport": string_field(&server, "transport"),
        "server_url": string_field(&server, "server_url"),
        "allowed_tools": string_array(&server, "allowed_tools"),
        "status": string_field(&server, "status").unwrap_or_else(|| "registered".to_string()),
        "source": string_field(&server, "source"),
        "server_hash": string_field(&server, "server_hash"),
        "plaintext_secret_material_returned": false,
        "js_projection_readback": false,
    }))
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rust_replays_only_mcp_servers_from_rust_authored_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record_dir = temp.path().join("mcp-servers");
        fs::create_dir_all(&record_dir).expect("record dir");
        fs::write(
            record_dir.join("import.json"),
            serde_json::to_string_pretty(&json!({
                "object": "ioi.model_mount_mcp_workflow",
                "operation_kind": "model_mount.mcp_server.import",
                "rust_core_boundary": "model_mount.mcp_workflow",
                "details": {
                    "servers": [{
                        "id": "mcp.docs",
                        "label": "Docs",
                        "transport": "remote",
                        "server_url": "https://example.test/mcp",
                        "allowed_tools": ["search"],
                        "status": "registered",
                        "source": "mcp.json",
                        "server_hash": "sha256:server"
                    }]
                }
            }))
            .expect("record json"),
        )
        .expect("write record");
        fs::write(
            record_dir.join("legacy.json"),
            serde_json::to_string_pretty(&json!({
                "object": "ioi.legacy_mcp_server",
                "id": "mcp.legacy"
            }))
            .expect("legacy json"),
        )
        .expect("write legacy");

        let projection = mcp_servers(&ModelMountReadProjectionRequest {
            projection_kind: "mcp_servers".to_string(),
            schema_version: None,
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            state: json!({}),
        })
        .expect("projection");

        assert_eq!(projection.as_array().expect("servers").len(), 1);
        assert_eq!(projection[0]["id"], "mcp.docs");
        assert_eq!(projection[0]["plaintext_secret_material_returned"], false);
    }
}
