use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_TOKENIZER_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountTokenizerRequest {
    pub schema_version: String,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub route_selection: Value,
    #[serde(default)]
    pub artifacts: Vec<Value>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountTokenizerPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub control_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountTokenizerBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountTokenizerRequest,
}

impl ModelMountTokenizerRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        if !matches!(
            self.operation.as_str(),
            "tokenize" | "count_tokens" | "context_fit"
        ) {
            return Err(ModelMountError::UnsupportedTokenizerOperation);
        }
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !self.route_selection.is_object() {
            return Err(ModelMountError::MissingField("route_selection"));
        }
        Ok(())
    }
}

pub fn plan_model_mount_tokenizer_response(
    request: ModelMountTokenizerBridgeRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_tokenizer(&request.request)?;
    let record_dir = plan.record_dir.clone();
    let record_id = plan.record_id.clone();
    let record = plan.record.clone();
    let receipt_refs = plan.receipt_refs.clone();
    let evidence_refs = plan.evidence_refs.clone();
    let control_hash = plan.control_hash.clone();
    let operation = plan.operation.clone();
    let rust_core_boundary = plan.rust_core_boundary.clone();
    Ok(json!({
        "source": "rust_model_mount_tokenizer_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_tokenizer".to_string()),
        "plan": plan,
        "record_dir": record_dir,
        "record_id": record_id,
        "record": record,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "operation": operation,
        "rust_core_boundary": rust_core_boundary,
    }))
}

pub(super) fn plan_tokenizer(
    request: &ModelMountTokenizerRequest,
) -> Result<ModelMountTokenizerPlan, ModelMountError> {
    request.validate()?;
    let body = object_or_empty(&request.body);
    let route_selection = object_or_non_empty(&request.route_selection, "route_selection")?;
    let route = object_field(route_selection, "route");
    let endpoint = object_field(route_selection, "endpoint");
    let provider = object_field(route_selection, "provider");
    let route_decision = object_field(route_selection, "route_decision")
        .or_else(|| object_field(route_selection, "routeDecision"));
    let route_receipt = object_field(route_selection, "route_receipt")
        .or_else(|| object_field(route_selection, "routeReceipt"))
        .or_else(|| object_field(route_selection, "accepted_receipt_record"));
    let route_control = object_field(route_selection, "route_control")
        .or_else(|| object_field(route_selection, "routeControl"));

    let operation = trimmed_string(&request.operation, "operation")?;
    let source = source_for(request);
    let input = string_field(body, "input").unwrap_or_default();
    let tokens = tokenize(&input);
    let token_count = tokens.len() as u64;
    let input_hash = format!("sha256:{}", sha256_hex(input.as_bytes())?);
    let route_id = route_ref(body, route_selection, route, route_decision)?;
    let model_id = model_ref(body, route_selection, endpoint, route_decision)?;
    let endpoint_id = endpoint_ref(route_selection, endpoint, route_decision)?;
    let provider_id = provider_ref(route_selection, provider, route_decision)?;
    let route_decision_ref = route_decision
        .and_then(|record| string_field(record, "route_decision_ref"))
        .or_else(|| {
            nested_string_field(
                route_receipt,
                &["details"],
                "model_mount_route_decision_ref",
            )
        });
    let route_decision_hash = route_decision
        .and_then(|record| string_field(record, "route_decision_hash"))
        .or_else(|| {
            nested_string_field(
                route_receipt,
                &["details"],
                "model_mount_route_decision_hash",
            )
        });
    let route_receipt_ref = route_receipt_ref(route_receipt);
    let receipt_refs = receipt_refs_for(request, route_decision, route_receipt, route_control)?;
    let evidence_refs = tokenizer_evidence_refs();
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let context = context_fit_values(request, endpoint, &tokens)?;
    let control_seed = json!({
        "operation": operation,
        "body": request.body,
        "route_selection": request.route_selection,
        "route_id": route_id,
        "model": model_id,
        "endpoint_id": endpoint_id,
        "provider_id": provider_id,
        "input_hash": input_hash,
        "receipt_refs": receipt_refs,
    });
    let control_hash = sha256_hex(
        &serde_json::to_vec(&control_seed)
            .map_err(|error| ModelMountError::HashFailed(error.to_string()))?,
    )?;
    let record_id = format!("model_tokenizer:{}:{}", operation, &control_hash[..16]);
    let record = json!({
        "id": record_id,
        "object": "ioi.model_mount_tokenizer_result",
        "status": "planned",
        "operation": operation,
        "source": source,
        "rust_core_boundary": "model_mount.tokenizer",
        "route_selection_boundary": "model_mount.route_selection",
        "route_id": route_id,
        "model": model_id,
        "endpoint_id": endpoint_id,
        "provider_id": provider_id,
        "route_decision_ref": route_decision_ref,
        "route_decision_hash": route_decision_hash,
        "route_receipt_ref": route_receipt_ref,
        "route_control_ref": route_control_ref(route_control),
        "required_scope": request.required_scope,
        "input_hash": input_hash,
        "tokens": tokens,
        "token_count": token_count,
        "usage": {
            "prompt_tokens": token_count,
            "total_tokens": token_count,
        },
        "context_window": context.context_window,
        "context_length": context.context_window,
        "max_output_tokens": context.max_output_tokens,
        "available_input_tokens": context.available_input_tokens,
        "fits": context.fits,
        "truncation": {
            "applied": context.truncated,
            "input_tokens": context.available_input_tokens,
            "fitted_input": context.truncated_input,
        },
        "fitted_input": context.truncated_input,
        "fitted_input_hash": context.truncated_input_hash,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "planned_at": generated_at,
    });
    Ok(ModelMountTokenizerPlan {
        schema_version: MODEL_MOUNT_TOKENIZER_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_tokenizer_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.tokenizer".to_string(),
        operation,
        source,
        record_dir: "model-tokenizer-utilities".to_string(),
        record_id,
        record,
        receipt_refs,
        evidence_refs,
        control_hash,
    })
}

#[derive(Debug)]
struct ContextFitValues {
    context_window: u64,
    max_output_tokens: u64,
    available_input_tokens: u64,
    fits: bool,
    truncated: bool,
    truncated_input: String,
    truncated_input_hash: String,
}

fn context_fit_values(
    request: &ModelMountTokenizerRequest,
    endpoint: Option<&Map<String, Value>>,
    tokens: &[String],
) -> Result<ContextFitValues, ModelMountError> {
    let body = object_or_empty(&request.body);
    let context_window = positive_integer_field(body, "context_length")
        .or_else(|| endpoint.and_then(endpoint_context_window))
        .or_else(|| artifact_context_window(request, endpoint))
        .unwrap_or(4096);
    let max_output_tokens = positive_integer_field(body, "max_output_tokens").unwrap_or(0);
    let available_input_tokens = context_window.saturating_sub(max_output_tokens);
    let token_count = tokens.len() as u64;
    let fits = token_count <= available_input_tokens;
    let truncated = !fits;
    let fitted_tokens = if truncated {
        tokens
            .iter()
            .take(available_input_tokens as usize)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        tokens.to_vec()
    };
    let truncated_input = fitted_tokens.join(" ");
    let truncated_input_hash = format!("sha256:{}", sha256_hex(truncated_input.as_bytes())?);
    Ok(ContextFitValues {
        context_window,
        max_output_tokens,
        available_input_tokens,
        fits,
        truncated,
        truncated_input,
        truncated_input_hash,
    })
}

fn route_ref(
    body: &Map<String, Value>,
    selection: &Map<String, Value>,
    route: Option<&Map<String, Value>>,
    route_decision: Option<&Map<String, Value>>,
) -> Result<String, ModelMountError> {
    route_decision
        .and_then(|record| string_field(record, "route_ref"))
        .or_else(|| string_field(selection, "route_id"))
        .or_else(|| route.and_then(|record| string_field(record, "id")))
        .or_else(|| string_field(body, "route_id"))
        .ok_or(ModelMountError::MissingField("route_id"))
}

fn model_ref(
    body: &Map<String, Value>,
    selection: &Map<String, Value>,
    endpoint: Option<&Map<String, Value>>,
    route_decision: Option<&Map<String, Value>>,
) -> Result<String, ModelMountError> {
    route_decision
        .and_then(|record| string_field(record, "model_ref"))
        .or_else(|| string_field(selection, "selected_model"))
        .or_else(|| endpoint.and_then(|record| string_field_any(record, &["model_id", "modelId"])))
        .or_else(|| string_field(body, "model"))
        .or_else(|| string_field(body, "model_id"))
        .ok_or(ModelMountError::MissingField("model"))
}

fn endpoint_ref(
    selection: &Map<String, Value>,
    endpoint: Option<&Map<String, Value>>,
    route_decision: Option<&Map<String, Value>>,
) -> Result<String, ModelMountError> {
    route_decision
        .and_then(|record| string_field(record, "endpoint_ref"))
        .or_else(|| string_field(selection, "endpoint_id"))
        .or_else(|| endpoint.and_then(|record| string_field(record, "id")))
        .ok_or(ModelMountError::MissingField("endpoint_id"))
}

fn provider_ref(
    selection: &Map<String, Value>,
    provider: Option<&Map<String, Value>>,
    route_decision: Option<&Map<String, Value>>,
) -> Result<String, ModelMountError> {
    route_decision
        .and_then(|record| string_field(record, "provider_ref"))
        .or_else(|| string_field(selection, "provider_id"))
        .or_else(|| provider.and_then(|record| string_field(record, "id")))
        .ok_or(ModelMountError::MissingField("provider_id"))
}

fn receipt_refs_for(
    request: &ModelMountTokenizerRequest,
    route_decision: Option<&Map<String, Value>>,
    route_receipt: Option<&Map<String, Value>>,
    route_control: Option<&Map<String, Value>>,
) -> Result<Vec<String>, ModelMountError> {
    let mut refs = Vec::new();
    for value in &request.receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    if let Some(decision_refs) = route_decision.and_then(|record| record.get("receipt_refs")) {
        for value in string_array_value(decision_refs) {
            push_unique_ref(&mut refs, &value);
        }
    }
    if let Some(route_receipt_ref) = route_receipt_ref(route_receipt) {
        push_unique_ref(&mut refs, &route_receipt_ref);
    }
    if let Some(control_ref) = route_control_ref(route_control) {
        push_unique_ref(&mut refs, &control_ref);
    }
    if refs.is_empty() {
        return Err(ModelMountError::MissingReceiptRef);
    }
    Ok(refs)
}

fn route_receipt_ref(route_receipt: Option<&Map<String, Value>>) -> Option<String> {
    route_receipt.and_then(|record| {
        string_field(record, "receipt_ref")
            .or_else(|| string_field(record, "id").map(|id| receipt_ref_from_id(&id)))
    })
}

fn route_control_ref(route_control: Option<&Map<String, Value>>) -> Option<String> {
    route_control.and_then(|record| {
        string_field(record, "object_ref").or_else(|| {
            let record_dir = string_field(record, "record_dir")?;
            let record_id = string_field(record, "record_id")?;
            Some(format!(
                "agentgres://model-mounting/records/{record_dir}/{record_id}"
            ))
        })
    })
}

fn receipt_ref_from_id(value: &str) -> String {
    if value.contains("://") {
        value.to_string()
    } else {
        format!("receipt://{value}")
    }
}

fn artifact_context_window(
    request: &ModelMountTokenizerRequest,
    endpoint: Option<&Map<String, Value>>,
) -> Option<u64> {
    let artifact_id =
        endpoint.and_then(|record| string_field_any(record, &["artifact_id", "artifactId"]));
    let model_id = endpoint.and_then(|record| string_field_any(record, &["model_id", "modelId"]));
    request
        .artifacts
        .iter()
        .filter_map(Value::as_object)
        .find(|artifact| {
            artifact_id
                .as_ref()
                .is_some_and(|id| string_field(artifact, "id").as_deref() == Some(id.as_str()))
                || model_id.as_ref().is_some_and(|id| {
                    string_field_any(artifact, &["model_id", "modelId"]).as_deref()
                        == Some(id.as_str())
                })
        })
        .and_then(|artifact| {
            positive_integer_field_any(
                artifact,
                &["context_length", "contextWindow", "context_window"],
            )
            .or_else(|| nested_positive_integer_field(artifact, "metadata", "contextWindow"))
            .or_else(|| nested_positive_integer_field(artifact, "metadata", "context_window"))
            .or_else(|| nested_positive_integer_field(artifact, "metadata", "context"))
        })
}

fn endpoint_context_window(endpoint: &Map<String, Value>) -> Option<u64> {
    positive_integer_field_any(
        endpoint,
        &["context_length", "contextWindow", "context_window"],
    )
}

fn source_for(request: &ModelMountTokenizerRequest) -> String {
    request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_tokenizer_command".to_string())
}

fn tokenizer_evidence_refs() -> Vec<String> {
    vec![
        "model_mount_tokenizer_rust_owned".to_string(),
        "model_mount_context_fit_rust_owned".to_string(),
        "model_mount_route_selection_rust_owned".to_string(),
        "agentgres_model_tokenizer_truth_required".to_string(),
    ]
}

fn tokenize(input: &str) -> Vec<String> {
    input
        .split_whitespace()
        .filter_map(non_empty_string)
        .collect()
}

fn object_or_empty(value: &Value) -> &Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    value
        .as_object()
        .unwrap_or_else(|| EMPTY.get_or_init(Map::new))
}

fn object_or_non_empty<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a Map<String, Value>, ModelMountError> {
    value
        .as_object()
        .filter(|map| !map.is_empty())
        .ok_or(ModelMountError::MissingField(field))
}

fn object_field<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Map<String, Value>> {
    map.get(field).and_then(Value::as_object)
}

fn string_field(map: &Map<String, Value>, field: &str) -> Option<String> {
    map.get(field)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn string_field_any(map: &Map<String, Value>, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| string_field(map, field))
}

fn nested_string_field(
    root: Option<&Map<String, Value>>,
    path: &[&str],
    field: &str,
) -> Option<String> {
    let mut current = root?;
    for segment in path {
        current = current.get(*segment).and_then(Value::as_object)?;
    }
    string_field(current, field)
}

fn positive_integer_field(map: &Map<String, Value>, field: &str) -> Option<u64> {
    map.get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
}

fn positive_integer_field_any(map: &Map<String, Value>, fields: &[&str]) -> Option<u64> {
    fields
        .iter()
        .find_map(|field| positive_integer_field(map, field))
}

fn nested_positive_integer_field(
    map: &Map<String, Value>,
    object_field: &str,
    field: &str,
) -> Option<u64> {
    map.get(object_field)
        .and_then(Value::as_object)
        .and_then(|nested| positive_integer_field(nested, field))
}

fn string_array_value(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(non_empty_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_selection() -> Value {
        json!({
            "route": { "id": "route.local-first" },
            "endpoint": {
                "id": "endpoint.local.llama",
                "modelId": "llama-test",
                "providerId": "provider.local",
                "artifactId": "artifact.llama"
            },
            "provider": { "id": "provider.local" },
            "route_decision": {
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local.llama",
                "model_ref": "llama-test",
                "capability": "tokenize",
                "route_decision_ref": "model_mount://route_decision/test",
                "route_decision_hash": "sha256:route-decision",
                "receipt_refs": ["receipt://route-selection/test"]
            },
            "route_receipt": {
                "id": "model-mount/route-control/model_mount.route.select/test"
            },
            "route_control": {
                "record_dir": "model-route-selections",
                "record_id": "route_selection:route.local-first:test"
            }
        })
    }

    #[test]
    fn tokenizer_control_is_planned_in_rust_model_mount() {
        let plan = plan_tokenizer(&ModelMountTokenizerRequest {
            schema_version: MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION.to_string(),
            operation: "tokenize".to_string(),
            source: Some("runtime-daemon.model_mounting.tokenizer".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            required_scope: Some("model.tokenize:*".to_string()),
            body: json!({
                "model": "llama-test",
                "route_id": "route.local-first",
                "input": "one two three",
            }),
            route_selection: route_selection(),
            artifacts: vec![json!({
                "id": "artifact.llama",
                "modelId": "llama-test",
                "contextWindow": 4,
            })],
            receipt_refs: vec![],
        })
        .expect("tokenizer plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_TOKENIZER_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.object, "ioi.model_mount_tokenizer_plan");
        assert_eq!(plan.rust_core_boundary, "model_mount.tokenizer");
        assert_eq!(plan.record_dir, "model-tokenizer-utilities");
        assert_eq!(plan.record["operation"], "tokenize");
        assert_eq!(plan.record["route_id"], "route.local-first");
        assert_eq!(plan.record["model"], "llama-test");
        assert_eq!(plan.record["token_count"], 3);
        assert_eq!(plan.record["tokens"], json!(["one", "two", "three"]));
        assert_eq!(
            plan.record["route_decision_ref"],
            "model_mount://route_decision/test"
        );
        assert!(plan
            .receipt_refs
            .contains(&"receipt://route-selection/test".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"model_mount_tokenizer_rust_owned".to_string()));
    }

    #[test]
    fn context_fit_uses_rust_context_window_and_truncation() {
        let plan = plan_tokenizer(&ModelMountTokenizerRequest {
            schema_version: MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION.to_string(),
            operation: "context_fit".to_string(),
            source: None,
            generated_at: None,
            required_scope: Some("model.context:*".to_string()),
            body: json!({
                "model": "llama-test",
                "route_id": "route.local-first",
                "input": "one two three four five",
                "max_output_tokens": 1,
            }),
            route_selection: route_selection(),
            artifacts: vec![json!({
                "id": "artifact.llama",
                "modelId": "llama-test",
                "contextWindow": 4,
            })],
            receipt_refs: vec![],
        })
        .expect("context fit plan");

        assert_eq!(plan.record["context_window"], 4);
        assert_eq!(plan.record["available_input_tokens"], 3);
        assert_eq!(plan.record["fits"], false);
        assert_eq!(plan.record["truncation"]["applied"], true);
        assert_eq!(plan.record["fitted_input"], "one two three");
        assert!(plan.record["fitted_input_hash"]
            .as_str()
            .expect("hash")
            .starts_with("sha256:"));
    }
}
