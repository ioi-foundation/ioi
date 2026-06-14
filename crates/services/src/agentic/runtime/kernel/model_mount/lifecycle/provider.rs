use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::{
    push_unique_ref, require_non_empty, ModelMountError,
    MODEL_MOUNT_PROVIDER_LIFECYCLE_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderLifecycleRequest {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub action: String,
    pub execution_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_status: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub process_evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderLifecycleResult {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub action: String,
    pub status: String,
    pub backend: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub evidence_refs: Vec<String>,
    pub lifecycle_hash: String,
    pub operation_kind: String,
    pub rust_core_boundary: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub public_response: Value,
    pub receipt_refs: Vec<String>,
}

impl ModelMountProviderLifecycleRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        if self.model_ref.trim().eq_ignore_ascii_case("auto") {
            return Err(ModelMountError::UnresolvedAutoModel);
        }
        if !matches!(self.action.trim(), "health" | "load" | "unload") {
            return Err(ModelMountError::UnsupportedProviderLifecycleAction);
        }
        if !is_native_local_provider_lifecycle_backend(self)
            && !is_fixture_provider_lifecycle_backend(self)
            && !is_hosted_provider_lifecycle_backend(self)
        {
            return Err(ModelMountError::UnsupportedProviderLifecycleBackend);
        }
        Ok(())
    }
}

pub(super) fn plan_provider_lifecycle(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
    request.validate()?;
    let operation_kind = provider_lifecycle_operation_kind(request);
    let receipt_refs = non_empty_vec(&request.receipt_refs);
    let mut result = ModelMountProviderLifecycleResult {
        schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
        provider_ref: request.provider_ref.clone(),
        provider_kind: request.provider_kind.clone(),
        endpoint_ref: request.endpoint_ref.clone(),
        model_ref: request.model_ref.clone(),
        action: request.action.clone(),
        status: provider_lifecycle_status(request)?,
        backend: provider_lifecycle_backend(request),
        backend_id: provider_lifecycle_backend_id(request),
        driver: provider_lifecycle_driver(request),
        execution_backend: request.execution_backend.clone(),
        evidence_refs: provider_lifecycle_evidence_refs(request),
        lifecycle_hash: String::new(),
        operation_kind,
        rust_core_boundary: "model_mount.provider_lifecycle".to_string(),
        record_dir: "model-provider-lifecycle-controls".to_string(),
        record_id: String::new(),
        record: Value::Null,
        public_response: Value::Null,
        receipt_refs,
    };
    result.lifecycle_hash = provider_lifecycle_hash(&result)?;
    result.record_id = provider_lifecycle_record_id(&result);
    result.public_response = provider_lifecycle_public_response(&result);
    result.record = provider_lifecycle_record(&result);
    Ok(result)
}

fn is_native_local_provider_lifecycle_backend(
    request: &ModelMountProviderLifecycleRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local_lifecycle" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_fixture_provider_lifecycle_backend(request: &ModelMountProviderLifecycleRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture_lifecycle" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

fn is_hosted_provider_lifecycle_backend(request: &ModelMountProviderLifecycleRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_hosted_provider_lifecycle" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    matches!(
        provider_kind,
        "openai"
            | "anthropic"
            | "gemini"
            | "custom_http"
            | "openai_compatible"
            | "ollama"
            | "vllm"
            | "llama_cpp"
            | "lm_studio"
            | "depin_tee"
    ) || matches!(
        api_format,
        "openai" | "anthropic" | "gemini" | "custom" | "openai_compatible" | "ollama"
    ) || matches!(
        driver,
        "openai_compatible" | "hosted_provider" | "hosted_provider_metadata"
    )
}

fn provider_lifecycle_status(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<String, ModelMountError> {
    match request.action.trim() {
        "health" => {
            if matches!(
                request.provider_status.as_deref().map(str::trim),
                Some("blocked")
            ) {
                Ok("blocked".to_string())
            } else {
                Ok("available".to_string())
            }
        }
        "load" => Ok("loaded".to_string()),
        "unload" => Ok("unloaded".to_string()),
        _ => Err(ModelMountError::UnsupportedProviderLifecycleAction),
    }
}

fn provider_lifecycle_backend(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        "autopilot.native_local.fixture".to_string()
    } else if is_hosted_provider_lifecycle_backend(request) {
        request
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                request
                    .driver
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or("hosted_provider_metadata")
            .to_string()
    } else {
        request
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("ioi_fixture")
            .to_string()
    }
}

fn provider_lifecycle_backend_id(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.autopilot.native-local.fixture")
            .to_string();
    }
    if is_hosted_provider_lifecycle_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "backend.hosted.{}",
                    record_id_segment(&request.provider_kind, "hosted")
                )
            });
    }
    request
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.fixture")
        .to_string()
}

fn provider_lifecycle_driver(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        "native_local".to_string()
    } else if is_hosted_provider_lifecycle_backend(request) {
        "hosted_provider_metadata".to_string()
    } else {
        "fixture".to_string()
    }
}

fn provider_lifecycle_evidence_refs(request: &ModelMountProviderLifecycleRequest) -> Vec<String> {
    let mut refs = vec![
        "public_provider_lifecycle_js_facade_retired".to_string(),
        "rust_model_mount_provider_lifecycle".to_string(),
        "agentgres_provider_lifecycle_truth_required".to_string(),
    ];
    if is_native_local_provider_lifecycle_backend(request) {
        refs.push("rust_model_mount_native_local_lifecycle_backend".to_string());
        if matches!(request.action.trim(), "health" | "load") {
            refs.push("autopilot_native_local_backend_registry".to_string());
        }
        if matches!(request.action.trim(), "load" | "unload") {
            refs.push("autopilot_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
    } else if is_hosted_provider_lifecycle_backend(request) {
        refs.push("rust_model_mount_hosted_provider_lifecycle_backend".to_string());
        refs.push("hosted_provider_transport_not_executed".to_string());
        refs.push("wallet_network_provider_lifecycle_authority_required".to_string());
    } else {
        refs.push("rust_model_mount_fixture_lifecycle_backend".to_string());
        refs.push("agentgres_model_registry_fixture".to_string());
        refs.push("deterministic_fixture".to_string());
    }
    for evidence_ref in request
        .process_evidence_refs
        .iter()
        .chain(request.evidence_refs.iter())
    {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn provider_lifecycle_hash(
    result: &ModelMountProviderLifecycleResult,
) -> Result<String, ModelMountError> {
    let canonical = json!({
        "schema_version": &result.schema_version,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "endpoint_ref": &result.endpoint_ref,
        "model_ref": &result.model_ref,
        "action": &result.action,
        "status": &result.status,
        "backend": &result.backend,
        "backend_id": &result.backend_id,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "operation_kind": &result.operation_kind,
        "rust_core_boundary": &result.rust_core_boundary,
        "evidence_refs": &result.evidence_refs,
        "receipt_refs": &result.receipt_refs,
    });
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_lifecycle_operation_kind(request: &ModelMountProviderLifecycleRequest) -> String {
    request
        .operation_kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| match request.action.trim() {
            "load" => "model_mount.provider.start".to_string(),
            "unload" => "model_mount.provider.stop".to_string(),
            _ => "model_mount.provider.health".to_string(),
        })
}

fn provider_lifecycle_record_id(result: &ModelMountProviderLifecycleResult) -> String {
    let provider = record_id_segment(&result.provider_ref, "provider");
    let action = record_id_segment(&result.action, "lifecycle");
    let hash = result
        .lifecycle_hash
        .strip_prefix("sha256:")
        .unwrap_or(&result.lifecycle_hash)
        .chars()
        .take(16)
        .collect::<String>();
    format!("provider_lifecycle_{provider}_{action}_{hash}")
}

fn provider_lifecycle_public_response(result: &ModelMountProviderLifecycleResult) -> Value {
    json!({
        "object": "ioi.model_mount_provider_lifecycle",
        "status": &result.status,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "endpoint_ref": &result.endpoint_ref,
        "model_ref": &result.model_ref,
        "action": &result.action,
        "backend_id": &result.backend_id,
        "provider_backend": &result.backend,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "operation_kind": &result.operation_kind,
        "rust_core_boundary": &result.rust_core_boundary,
        "lifecycle_hash": &result.lifecycle_hash,
        "js_provider_driver_call": false,
        "js_provider_map_write": false,
        "js_lifecycle_receipt": false,
        "js_projection_write": false,
    })
}

fn provider_lifecycle_record(result: &ModelMountProviderLifecycleResult) -> Value {
    let mut record_receipt_refs = result.receipt_refs.clone();
    push_unique_ref(&mut record_receipt_refs, &result.lifecycle_hash);
    json!({
        "id": &result.record_id,
        "record_id": &result.record_id,
        "object": "ioi.model_mount_provider_lifecycle",
        "schema_version": MODEL_MOUNT_PROVIDER_LIFECYCLE_PLAN_SCHEMA_VERSION,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "endpoint_ref": &result.endpoint_ref,
        "model_ref": &result.model_ref,
        "action": &result.action,
        "operation_kind": &result.operation_kind,
        "status": &result.status,
        "backend": &result.backend,
        "backend_id": &result.backend_id,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "lifecycle_hash": &result.lifecycle_hash,
        "record_dir": &result.record_dir,
        "receipt_refs": record_receipt_refs,
        "rust_core_boundary": &result.rust_core_boundary,
        "source": "rust_model_mount_provider_lifecycle_command",
        "public_response": &result.public_response,
        "evidence_refs": &result.evidence_refs,
    })
}

fn record_id_segment(value: &str, fallback: &str) -> String {
    let mut segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while segment.contains("__") {
        segment = segment.replace("__", "_");
    }
    let segment = segment.trim_matches('_');
    if segment.is_empty() {
        fallback.to_string()
    } else {
        segment.to_string()
    }
}

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_lifecycle_request() -> ModelMountProviderLifecycleRequest {
        ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            provider_kind: "ioi_native_local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            action: "load".to_string(),
            execution_backend: "rust_model_mount_native_local_lifecycle".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_model_load_request".to_string()],
            process_evidence_refs: vec!["autopilot_native_local_process_started".to_string()],
            operation_kind: Some("model_mount.provider.start".to_string()),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_refs: vec!["receipt://provider-lifecycle".to_string()],
        }
    }

    fn fixture_provider_lifecycle_request() -> ModelMountProviderLifecycleRequest {
        ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://fixture".to_string(),
            provider_kind: "local_folder".to_string(),
            endpoint_ref: "endpoint://fixture/qwen3".to_string(),
            model_ref: "model://fixture/qwen3".to_string(),
            action: "health".to_string(),
            execution_backend: "rust_model_mount_fixture_lifecycle".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_fixture_health_request".to_string()],
            process_evidence_refs: vec![],
            operation_kind: Some("model_mount.provider.health".to_string()),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_refs: vec![],
        }
    }

    #[test]
    fn provider_lifecycle_child_module_owns_planner_surface() {
        let result = plan_provider_lifecycle(&provider_lifecycle_request())
            .expect("native-local provider lifecycle planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_lifecycle"
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_lifecycle".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_process_started".to_string()));
        assert!(result.lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = provider_lifecycle_request();
        request.action = "unload".to_string();
        request.evidence_refs.clear();

        let result = plan_provider_lifecycle(&request)
            .expect("native-local provider unload lifecycle planned in Rust");

        assert_eq!(result.action, "unload");
        assert_eq!(result.status, "unloaded");
        assert!(!result
            .evidence_refs
            .contains(&"autopilot_native_local_backend_registry".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_health_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = provider_lifecycle_request();
        request.action = "health".to_string();
        request.evidence_refs = vec!["daemon_native_local_health_request".to_string()];
        request.process_evidence_refs.clear();

        let result = plan_provider_lifecycle(&request)
            .expect("native-local provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(result.status, "available");
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_backend_registry".to_string()));
        assert!(!result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));

        request.provider_status = Some("blocked".to_string());
        let result = plan_provider_lifecycle(&request)
            .expect("blocked native-local provider health planned in Rust");

        assert_eq!(result.status, "blocked");
    }

    #[test]
    fn fixture_provider_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = fixture_provider_lifecycle_request();

        let result =
            plan_provider_lifecycle(&request).expect("fixture provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(result.status, "available");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert_eq!(result.driver, "fixture");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_registry_fixture".to_string()));

        request.action = "load".to_string();
        let result =
            plan_provider_lifecycle(&request).expect("fixture provider load planned in Rust");
        assert_eq!(result.status, "loaded");

        request.action = "unload".to_string();
        let result =
            plan_provider_lifecycle(&request).expect("fixture provider unload planned in Rust");
        assert_eq!(result.status, "unloaded");
    }

    #[test]
    fn hosted_provider_lifecycle_is_planned_without_transport_execution() {
        let request = ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://openai".to_string(),
            provider_kind: "custom_http".to_string(),
            endpoint_ref: "endpoint://openai/hosted-metadata".to_string(),
            model_ref: "model://custom_http/hosted-metadata".to_string(),
            action: "health".to_string(),
            execution_backend: "rust_model_mount_hosted_provider_lifecycle".to_string(),
            api_format: Some("openai_compatible".to_string()),
            driver: Some("hosted_provider_metadata".to_string()),
            backend_ref: Some("backend.hosted.custom_http".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_hosted_health_request".to_string()],
            process_evidence_refs: vec![],
            operation_kind: Some("model_mount.provider.health".to_string()),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-14T00:00:00.000Z".to_string()),
            receipt_refs: vec![],
        };

        let result = plan_provider_lifecycle(&request)
            .expect("hosted provider metadata lifecycle planned in Rust");

        assert_eq!(result.status, "available");
        assert_eq!(result.backend, "openai_compatible");
        assert_eq!(result.driver, "hosted_provider_metadata");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_hosted_provider_lifecycle"
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_hosted_provider_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"hosted_provider_transport_not_executed".to_string()));
        assert!(result.public_response["js_provider_driver_call"] == false);
    }

    #[test]
    fn native_local_provider_lifecycle_rejects_unsupported_backend_and_action() {
        let mut request = provider_lifecycle_request();
        request.execution_backend = "daemon_js".to_string();

        let error = plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleBackend);

        request = provider_lifecycle_request();
        request.action = "restart".to_string();
        let error = plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner only supports explicit health/load/unload actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleAction);
    }
}
