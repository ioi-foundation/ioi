use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, require_non_empty, sha256_hex, trimmed_string, ModelMountError,
    MODEL_MOUNT_RECEIPT_GATE_PLAN_SCHEMA_VERSION, MODEL_MOUNT_RECEIPT_GATE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReceiptGateRequest {
    pub schema_version: String,
    pub operation_kind: String,
    pub receipt_id: String,
    #[serde(default)]
    pub receipt: Value,
    #[serde(default)]
    pub required_tool_receipt_ids: Vec<String>,
    #[serde(default)]
    pub tool_receipts: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_redaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_route_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_selected_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_endpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_backend_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReceiptGatePlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation_kind: String,
    pub receipt_id: String,
    pub gate_status: String,
    pub failures: Vec<String>,
    pub receipt: Value,
    pub public_response: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub gate_hash: String,
    pub receipt_binding_ref: String,
    pub agentgres_operation_ref: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountReceiptGateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountReceiptGateRequest,
}

impl ModelMountReceiptGateRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_RECEIPT_GATE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_RECEIPT_GATE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if self.operation_kind != "workflow_receipt_gate" {
            return Err(ModelMountError::UnsupportedReceiptGateOperation);
        }
        require_non_empty("receipt_id", &self.receipt_id)?;
        if !self.receipt.is_object() {
            return Err(ModelMountError::MissingField("receipt"));
        }
        Ok(())
    }
}

pub fn plan_model_mount_receipt_gate_response(
    request: ModelMountReceiptGateBridgeRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_receipt_gate(&request.request)?;
    let receipt = plan.receipt.clone();
    let public_response = plan.public_response.clone();
    let receipt_refs = plan.receipt_refs.clone();
    let evidence_refs = plan.evidence_refs.clone();
    let gate_hash = plan.gate_hash.clone();
    let operation_kind = plan.operation_kind.clone();
    let rust_core_boundary = plan.rust_core_boundary.clone();
    Ok(json!({
        "source": "rust_model_mount_receipt_gate_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_receipt_gate".to_string()),
        "plan": plan,
        "receipt": receipt,
        "public_response": public_response,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "gate_hash": gate_hash,
        "operation_kind": operation_kind,
        "rust_core_boundary": rust_core_boundary,
    }))
}

pub(super) fn plan_receipt_gate(
    request: &ModelMountReceiptGateRequest,
) -> Result<ModelMountReceiptGatePlan, ModelMountError> {
    request.validate()?;
    let receipt = object_or_empty(&request.receipt);
    let details = match object_field(receipt, "details") {
        Some(details) => details,
        None => empty_map(),
    };
    let receipt_id = trimmed_string(&request.receipt_id, "receipt_id")?;
    let route_id = string_field(details, "route_id");
    let selected_model = string_field(details, "selected_model");
    let endpoint_id = string_field(details, "endpoint_id");
    let backend_id =
        string_field(details, "backend_id").or_else(|| string_field(details, "selected_backend"));
    let tool_receipt_ids = string_array_field(details, "tool_receipt_ids");
    let mut failures = Vec::new();

    if let Some(required) = request
        .required_redaction
        .as_ref()
        .and_then(|value| non_empty_string(value))
    {
        let actual = string_field(receipt, "redaction");
        if actual.as_deref() != Some(required.as_str()) {
            failures.push(format!(
                "redaction:{}",
                actual.unwrap_or_else(|| "missing".to_string())
            ));
        }
    }
    compare_required(
        &mut failures,
        "route",
        route_id.as_deref(),
        request.required_route_id.as_deref(),
    );
    compare_required(
        &mut failures,
        "selected_model",
        selected_model.as_deref(),
        request.required_selected_model.as_deref(),
    );
    compare_required(
        &mut failures,
        "endpoint",
        endpoint_id.as_deref(),
        request.required_endpoint_id.as_deref(),
    );
    compare_required(
        &mut failures,
        "backend",
        backend_id.as_deref(),
        request.required_backend_id.as_deref(),
    );

    for required_id in non_empty_vec(&request.required_tool_receipt_ids) {
        let tool_receipt = request
            .tool_receipts
            .iter()
            .find(|receipt| {
                receipt
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(non_empty_string)
                    .as_deref()
                    == Some(required_id.as_str())
            })
            .and_then(Value::as_object);
        let tool_kind = tool_receipt.and_then(|record| string_field(record, "kind"));
        if tool_kind.as_deref() != Some("mcp_tool_invocation") {
            failures.push(format!("tool_receipt_kind:{required_id}"));
        }
        if !tool_receipt_ids.iter().any(|value| value == &required_id) {
            failures.push(format!("tool_receipt_link:{required_id}"));
        }
    }

    let gate_status = if failures.is_empty() {
        "passed".to_string()
    } else {
        "blocked".to_string()
    };
    let receipt_kind = if failures.is_empty() {
        "workflow_receipt_gate"
    } else {
        "workflow_receipt_gate_blocked"
    };
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let gate_seed = json!({
        "schema_version": request.schema_version,
        "operation_kind": request.operation_kind,
        "receipt_id": receipt_id,
        "gate_status": gate_status,
        "failures": failures,
        "required_tool_receipt_ids": non_empty_vec(&request.required_tool_receipt_ids),
        "route_id": route_id,
        "selected_model": selected_model,
        "endpoint_id": endpoint_id,
        "backend_id": backend_id,
    });
    let gate_hash = format!("sha256:{}", hash_json(&gate_seed)?);
    let receipt_binding_ref = format!(
        "sha256:{}",
        hash_json(&json!({
            "gate_hash": gate_hash,
            "receipt_id": receipt_id,
            "receipt_refs": receipt_refs_for(&receipt_id, &request.required_tool_receipt_ids),
        }))?
    );
    let agentgres_operation_ref = format!(
        "agentgres://model-mounting/receipt-gates/{}",
        &gate_hash.trim_start_matches("sha256:")[..16]
    );
    let state_root_before = format!(
        "sha256:{}",
        hash_json(&json!({"receipt_id": receipt_id, "gate_status": "before"}))?
    );
    let state_root_after = format!(
        "sha256:{}",
        hash_json(&json!({"gate_hash": gate_hash, "gate_status": gate_status}))?
    );
    let resulting_head = format!(
        "agentgres://model-mounting/receipt-gates/head/{}",
        &state_root_after.trim_start_matches("sha256:")[..16]
    );
    let evidence_refs = receipt_gate_evidence_refs();
    let receipt_refs = receipt_refs_for(&receipt_id, &request.required_tool_receipt_ids);
    let public_response = json!({
        "object": "ioi.model_mount_receipt_gate_result",
        "status": gate_status,
        "receipt_id": receipt_id,
        "gate_receipt_id": format!("receipt.{}.{}", receipt_kind, &gate_hash.trim_start_matches("sha256:")[..16]),
        "failures": failures,
        "required_tool_receipt_ids": non_empty_vec(&request.required_tool_receipt_ids),
        "rust_core_boundary": "model_mount.receipt_gate",
        "gate_hash": gate_hash,
    });
    let gate_receipt_id = public_response
        .get("gate_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("receipt.workflow_receipt_gate")
        .to_string();
    let gate_receipt = json!({
        "id": gate_receipt_id,
        "kind": receipt_kind,
        "redaction": string_field(receipt, "redaction").unwrap_or_else(|| "redacted".to_string()),
        "summary": if failures.is_empty() {
            "Rust model_mount receipt gate passed"
        } else {
            "Rust model_mount receipt gate blocked"
        },
        "createdAt": generated_at,
        "evidenceRefs": evidence_refs,
        "details": {
            "boundary": "model_mount.receipt_gate",
            "operation_kind": request.operation_kind,
            "receipt_id": receipt_id,
            "gate_status": gate_status,
            "failures": failures,
            "route_id": route_id,
            "selected_model": selected_model,
            "endpoint_id": endpoint_id,
            "backend_id": backend_id,
            "required_tool_receipt_ids": non_empty_vec(&request.required_tool_receipt_ids),
            "receipt_refs": receipt_refs,
            "model_mount_receipt_gate_hash": gate_hash,
            "model_mount_receipt_binding_ref": receipt_binding_ref,
            "model_mount_agentgres_operation_ref": agentgres_operation_ref,
            "model_mount_agentgres_state_root_before": state_root_before,
            "model_mount_agentgres_state_root_after": state_root_after,
            "model_mount_agentgres_resulting_head": resulting_head,
            "source": source,
        },
    });

    Ok(ModelMountReceiptGatePlan {
        schema_version: MODEL_MOUNT_RECEIPT_GATE_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_receipt_gate_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.receipt_gate".to_string(),
        operation_kind: request.operation_kind.clone(),
        receipt_id,
        gate_status,
        failures,
        receipt: gate_receipt,
        public_response,
        receipt_refs,
        evidence_refs,
        gate_hash,
        receipt_binding_ref,
        agentgres_operation_ref,
        state_root_before,
        state_root_after,
        resulting_head,
    })
}

fn receipt_gate_evidence_refs() -> Vec<String> {
    vec![
        "model_mount_receipt_gate_rust_owned".to_string(),
        "model_mount_receipt_gate_js_facade_retired".to_string(),
        "rust_receipt_binder_core".to_string(),
        "agentgres_model_receipt_gate_truth_required".to_string(),
    ]
}

fn compare_required(
    failures: &mut Vec<String>,
    label: &str,
    actual: Option<&str>,
    required: Option<&str>,
) {
    let Some(required) = required.and_then(non_empty_string) else {
        return;
    };
    if actual != Some(required.as_str()) {
        failures.push(format!("{}:{}", label, actual.unwrap_or("missing")));
    }
}

fn receipt_refs_for(receipt_id: &str, required_tool_receipt_ids: &[String]) -> Vec<String> {
    let mut refs = vec![receipt_id.to_string()];
    for value in required_tool_receipt_ids {
        if let Some(value) = non_empty_string(value) {
            if !refs.iter().any(|existing| existing == &value) {
                refs.push(value);
            }
        }
    }
    refs
}

fn object_or_empty<'a>(value: &'a Value) -> &'a Map<String, Value> {
    match value.as_object() {
        Some(map) => map,
        None => empty_map(),
    }
}

fn object_field<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Map<String, Value>> {
    map.get(field).and_then(Value::as_object)
}

fn empty_map() -> &'static Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

fn string_field(map: &Map<String, Value>, field: &str) -> Option<String> {
    map.get(field)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn string_array_field(map: &Map<String, Value>, field: &str) -> Vec<String> {
    map.get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(non_empty_string)
                .collect()
        })
        .unwrap_or_default()
}

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| non_empty_string(value))
        .collect()
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    serde_json::to_vec(value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))
        .and_then(|bytes| sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ModelMountReceiptGateRequest {
        ModelMountReceiptGateRequest {
            schema_version: MODEL_MOUNT_RECEIPT_GATE_SCHEMA_VERSION.to_string(),
            operation_kind: "workflow_receipt_gate".to_string(),
            receipt_id: "receipt-route".to_string(),
            receipt: json!({
                "id": "receipt-route",
                "kind": "model_invocation",
                "redaction": "redacted",
                "details": {
                    "route_id": "route.local-first",
                    "selected_model": "model.local",
                    "endpoint_id": "endpoint.local",
                    "backend_id": "backend.local",
                    "tool_receipt_ids": ["receipt-tool"],
                },
            }),
            required_tool_receipt_ids: vec!["receipt-tool".to_string()],
            tool_receipts: vec![json!({
                "id": "receipt-tool",
                "kind": "mcp_tool_invocation",
                "redaction": "redacted",
                "details": {},
            })],
            required_redaction: Some("redacted".to_string()),
            required_route_id: Some("route.local-first".to_string()),
            required_selected_model: Some("model.local".to_string()),
            required_endpoint_id: Some("endpoint.local".to_string()),
            required_backend_id: Some("backend.local".to_string()),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
        }
    }

    #[test]
    fn rust_core_plans_matching_receipt_gate() {
        let plan = plan_receipt_gate(&request()).expect("receipt gate plan");

        assert_eq!(plan.gate_status, "passed");
        assert!(plan.failures.is_empty());
        assert_eq!(plan.receipt["kind"], "workflow_receipt_gate");
        assert_eq!(
            plan.receipt["details"]["model_mount_receipt_binding_ref"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"),
            true
        );
        assert!(plan
            .evidence_refs
            .contains(&"model_mount_receipt_gate_rust_owned".to_string()));
    }

    #[test]
    fn rust_core_plans_blocked_receipt_gate() {
        let mut request = request();
        request.required_route_id = Some("route.other".to_string());
        request.tool_receipts[0]["kind"] = json!("model_invocation");
        let plan = plan_receipt_gate(&request).expect("blocked receipt gate plan");

        assert_eq!(plan.gate_status, "blocked");
        assert_eq!(plan.receipt["kind"], "workflow_receipt_gate_blocked");
        assert_eq!(
            plan.failures,
            vec![
                "route:route.local-first".to_string(),
                "tool_receipt_kind:receipt-tool".to_string(),
            ]
        );
    }
}
