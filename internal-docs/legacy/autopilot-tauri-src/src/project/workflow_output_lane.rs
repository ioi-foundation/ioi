// apps/autopilot/src-tauri/src/project/workflow_output_lane.rs

use super::workflow_binding_lane::workflow_node_schema;
use super::*;

pub(super) fn workflow_output_satisfies_schema(node: &Value, output: &Value) -> Result<(), String> {
    let Some(schema) = workflow_node_schema(node, "outputSchema") else {
        return Ok(());
    };
    workflow_output_satisfies_test_schema(&schema, output)
}

pub(super) fn workflow_truncate_output(value: &[u8], limit: usize) -> String {
    let capped = if value.len() > limit {
        &value[..limit]
    } else {
        value
    };
    String::from_utf8_lossy(capped).to_string()
}

pub(super) fn workflow_output_bundle(
    node_id: &str,
    node_name: &str,
    logic: &Value,
    input: Value,
) -> Value {
    let format = logic
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("markdown")
        .to_string();
    let renderer_ref = logic
        .get("rendererRef")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowRendererRef>(value).ok());
    let delivery_target = logic
        .get("deliveryTarget")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowDeliveryTarget>(value).ok());
    let version = logic
        .get("versioning")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowOutputVersioning>(value).ok());
    let materialized_assets = logic
        .get("materialization")
        .and_then(Value::as_object)
        .filter(|materialization| {
            materialization
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .map(|materialization| {
            vec![WorkflowMaterializedAsset {
                id: unique_runtime_id("asset"),
                node_id: node_id.to_string(),
                asset_kind: materialization
                    .get("assetKind")
                    .and_then(Value::as_str)
                    .unwrap_or("file")
                    .to_string(),
                path: materialization
                    .get("assetPath")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_string),
                hash: None,
                created_at_ms: now_ms(),
            }]
        })
        .unwrap_or_default();
    let bundle = WorkflowOutputBundle {
        id: unique_runtime_id("output"),
        node_id: node_id.to_string(),
        format,
        value: input,
        renderer_ref,
        materialized_assets,
        delivery_target,
        dependency_refs: Vec::new(),
        evidence_refs: Vec::new(),
        version,
        created_at_ms: now_ms(),
    };
    json!({
        "nodeId": node_id,
        "kind": "output",
        "outputName": node_name,
        "outputBundle": bundle
    })
}
