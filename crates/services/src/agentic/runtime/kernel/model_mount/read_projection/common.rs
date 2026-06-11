use serde_json::Value;

use super::super::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;
use super::ModelMountReadProjectionRequest;

pub(super) fn model_mount_projection_schema_version(
    request: &ModelMountReadProjectionRequest,
) -> String {
    request
        .schema_version
        .clone()
        .unwrap_or_else(|| MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string())
}

pub(super) fn model_mount_projection_generated_at(
    request: &ModelMountReadProjectionRequest,
) -> String {
    request
        .generated_at
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
}

pub(super) fn array_field(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

pub(super) fn object_or_null(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(_)) => value.cloned().unwrap_or(Value::Null),
        Some(Value::Null) | None => Value::Null,
        Some(other) => other.clone(),
    }
}

pub(super) fn receipts_by_kind(receipts: &[Value], kind: &str) -> Vec<Value> {
    receipts
        .iter()
        .filter(|receipt| json_string_field(receipt, "kind").as_deref() == Some(kind))
        .cloned()
        .collect()
}

pub(super) fn json_string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(
        schema_version: Option<String>,
        generated_at: Option<String>,
    ) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "projection".to_string(),
            schema_version,
            generated_at,
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            base_url: None,
            state: json!({}),
        }
    }

    #[test]
    fn projection_common_defaults_live_outside_root_dispatcher() {
        let defaulted = request(None, None);
        let explicit = request(
            Some("schema.explicit".to_string()),
            Some("2026-06-11T12:00:00.000Z".to_string()),
        );

        assert_eq!(
            model_mount_projection_schema_version(&defaulted),
            MODEL_MOUNT_RUNTIME_SCHEMA_VERSION
        );
        assert_eq!(
            model_mount_projection_generated_at(&defaulted),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            model_mount_projection_schema_version(&explicit),
            "schema.explicit"
        );
        assert_eq!(
            model_mount_projection_generated_at(&explicit),
            "2026-06-11T12:00:00.000Z"
        );
    }

    #[test]
    fn projection_common_extracts_arrays_objects_and_receipt_kinds() {
        let value = json!({
            "array": [{"id": "one"}],
            "object": {"id": "object"},
            "string": "value",
            "receipts": [
                {"id": "route", "kind": "model_route_selection"},
                {"id": "health", "kind": "provider_health"},
                {"id": "route-2", "kind": "model_route_selection"}
            ]
        });
        let receipts = array_field(&value, "receipts");

        assert_eq!(array_field(&value, "array").len(), 1);
        assert_eq!(array_field(&value, "missing").len(), 0);
        assert_eq!(object_or_null(value.get("object"))["id"], "object");
        assert_eq!(object_or_null(value.get("string")), json!("value"));
        assert_eq!(
            receipts_by_kind(&receipts, "model_route_selection")
                .iter()
                .map(|receipt| json_string_field(receipt, "id").expect("id"))
                .collect::<Vec<_>>(),
            vec!["route".to_string(), "route-2".to_string()],
        );
    }
}
