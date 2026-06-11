use serde_json::Value;

use super::common::{array_field, json_string_field};
use super::ModelMountReadProjectionRequest;

pub(super) fn route_decisions(request: &ModelMountReadProjectionRequest) -> Value {
    Value::Array(route_decisions_from_receipts(&array_field(
        &request.state,
        "receipts",
    )))
}

pub(super) fn route_decisions_from_receipts(receipts: &[Value]) -> Vec<Value> {
    receipts
        .iter()
        .filter(|receipt| {
            json_string_field(receipt, "kind").as_deref() == Some("model_route_selection")
        })
        .filter_map(route_decision_from_receipt)
        .collect()
}

fn route_decision_from_receipt(receipt: &Value) -> Option<Value> {
    let mut decision = receipt
        .get("details")
        .and_then(|details| details.get("model_route_decision"))
        .and_then(Value::as_object)
        .cloned()?;
    decision.insert(
        "receipt_id".to_string(),
        receipt.get("id").cloned().unwrap_or(Value::Null),
    );
    decision.insert(
        "receipt_created_at".to_string(),
        receipt.get("createdAt").cloned().unwrap_or(Value::Null),
    );
    decision.insert(
        "receipt_kind".to_string(),
        receipt.get("kind").cloned().unwrap_or(Value::Null),
    );
    Some(Value::Object(decision))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;
    use serde_json::json;

    fn request(state: Value) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "model_route_decisions".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            base_url: None,
            state,
        }
    }

    #[test]
    fn route_decisions_have_dedicated_receipt_projection_owner() {
        let decisions = route_decisions(&request(json!({
            "receipts": [
                {"id": "receipt-other", "kind": "provider_health"},
                {
                    "id": "receipt-route",
                    "createdAt": "2026-06-11T00:02:00.000Z",
                    "kind": "model_route_selection",
                    "details": {"model_route_decision": {"route_id": "route.local-first"}}
                }
            ],
            "routes": [{"id": "route.js"}]
        })));

        let decisions = decisions.as_array().expect("route decisions");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["route_id"], "route.local-first");
        assert_eq!(decisions[0]["receipt_id"], "receipt-route");
        assert_eq!(decisions[0]["receipt_kind"], "model_route_selection");
    }
}
