use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::{
    push_unique_ref, require_non_empty, ModelMountError,
    MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderInventoryRequest {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
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
    pub item_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderInventoryResult {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub action: String,
    pub operation_kind: String,
    pub status: String,
    pub backend: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub item_refs: Vec<String>,
    pub item_count: usize,
    pub evidence_refs: Vec<String>,
    pub inventory_hash: String,
    pub rust_core_boundary: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub receipt_refs: Vec<String>,
}

impl ModelMountProviderInventoryRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        if !matches!(self.action.trim(), "list_models" | "list_loaded") {
            return Err(ModelMountError::UnsupportedProviderInventoryAction);
        }
        if !is_native_local_provider_inventory_backend(self)
            && !is_fixture_provider_inventory_backend(self)
            && !is_hosted_provider_inventory_backend(self)
        {
            return Err(ModelMountError::UnsupportedProviderInventoryBackend);
        }
        for item_ref in &self.item_refs {
            require_non_empty("item_refs[]", item_ref)?;
        }
        Ok(())
    }
}

pub(super) fn plan_provider_inventory(
    request: &ModelMountProviderInventoryRequest,
) -> Result<ModelMountProviderInventoryResult, ModelMountError> {
    request.validate()?;
    let mut result = ModelMountProviderInventoryResult {
        schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
        provider_ref: request.provider_ref.clone(),
        provider_kind: request.provider_kind.clone(),
        action: request.action.clone(),
        operation_kind: provider_inventory_operation_kind(request),
        status: "listed".to_string(),
        backend: provider_inventory_backend(request),
        backend_id: provider_inventory_backend_id(request),
        driver: provider_inventory_driver(request),
        execution_backend: request.execution_backend.clone(),
        item_refs: request.item_refs.clone(),
        item_count: request.item_refs.len(),
        evidence_refs: provider_inventory_evidence_refs(request),
        inventory_hash: String::new(),
        rust_core_boundary: "model_mount.provider_inventory".to_string(),
        record_dir: "model-provider-inventory".to_string(),
        record_id: String::new(),
        record: Value::Null,
        receipt_refs: vec![],
    };
    result.inventory_hash = provider_inventory_hash(&result)?;
    result.record_id = provider_inventory_record_id(&result);
    result.record = provider_inventory_record(&result);
    Ok(result)
}

fn provider_inventory_operation_kind(request: &ModelMountProviderInventoryRequest) -> String {
    match request.action.trim() {
        "list_loaded" => "model_mount.provider.inventory.list_loaded".to_string(),
        _ => "model_mount.provider.inventory.list_models".to_string(),
    }
}

fn is_native_local_provider_inventory_backend(
    request: &ModelMountProviderInventoryRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local_inventory" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_fixture_provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture_inventory" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

fn is_hosted_provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_hosted_provider_inventory" {
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

fn provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        "autopilot.native_local.fixture".to_string()
    } else if is_hosted_provider_inventory_backend(request) {
        "hosted_provider_metadata".to_string()
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

fn provider_inventory_backend_id(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.autopilot.native-local.fixture")
            .to_string();
    }
    if is_hosted_provider_inventory_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "backend.hosted.{}",
                    record_id_segment(&request.provider_kind, "provider")
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

fn provider_inventory_driver(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        "native_local".to_string()
    } else if is_hosted_provider_inventory_backend(request) {
        "hosted_provider_metadata".to_string()
    } else {
        "fixture".to_string()
    }
}

fn provider_inventory_evidence_refs(request: &ModelMountProviderInventoryRequest) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_provider_inventory".to_string(),
        "agentgres_provider_inventory_truth_required".to_string(),
    ];
    if is_native_local_provider_inventory_backend(request) {
        refs.push("rust_model_mount_native_local_inventory_backend".to_string());
        refs.push("autopilot_native_local_backend_registry".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("autopilot_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
    } else if is_hosted_provider_inventory_backend(request) {
        refs.push("rust_model_mount_hosted_provider_inventory_backend".to_string());
        refs.push("hosted_provider_transport_not_executed".to_string());
        refs.push("wallet_network_provider_secret_boundary".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("hosted_provider_loaded_instance_replay_required".to_string());
        } else {
            refs.push("hosted_provider_catalog_metadata_recorded".to_string());
        }
    } else {
        refs.push("rust_model_mount_fixture_inventory_backend".to_string());
        refs.push("agentgres_model_registry_fixture".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("agentgres_model_instance_registry_fixture".to_string());
        }
        refs.push("deterministic_fixture".to_string());
    }
    for evidence_ref in &request.evidence_refs {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn provider_inventory_hash(
    result: &ModelMountProviderInventoryResult,
) -> Result<String, ModelMountError> {
    let canonical = json!({
        "schema_version": &result.schema_version,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "action": &result.action,
        "operation_kind": &result.operation_kind,
        "status": &result.status,
        "backend": &result.backend,
        "backend_id": &result.backend_id,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "item_refs": &result.item_refs,
        "item_count": result.item_count,
        "evidence_refs": &result.evidence_refs,
        "rust_core_boundary": &result.rust_core_boundary,
    });
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_inventory_record_id(result: &ModelMountProviderInventoryResult) -> String {
    let provider = record_id_segment(&result.provider_ref, "provider");
    let action = record_id_segment(&result.action, "inventory");
    let hash = result
        .inventory_hash
        .strip_prefix("sha256:")
        .unwrap_or(&result.inventory_hash)
        .chars()
        .take(16)
        .collect::<String>();
    format!("provider_inventory_{provider}_{action}_{hash}")
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

fn provider_inventory_record(result: &ModelMountProviderInventoryResult) -> Value {
    json!({
        "id": &result.record_id,
        "object": "ioi.model_mount_provider_inventory",
        "schema_version": &result.schema_version,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "action": &result.action,
        "operation_kind": &result.operation_kind,
        "status": &result.status,
        "backend": &result.backend,
        "backend_id": &result.backend_id,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "item_refs": &result.item_refs,
        "item_count": result.item_count,
        "inventory_hash": &result.inventory_hash,
        "record_dir": &result.record_dir,
        "record_id": &result.record_id,
        "receipt_refs": &result.receipt_refs,
        "rust_core_boundary": &result.rust_core_boundary,
        "source": "rust_model_mount_provider_inventory_command",
        "evidence_refs": &result.evidence_refs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            provider_kind: "ioi_native_local".to_string(),
            action: "list_loaded".to_string(),
            execution_backend: "rust_model_mount_native_local_inventory".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            item_refs: vec!["model_instance://native/qwen3".to_string()],
            evidence_refs: vec!["daemon_native_local_list_loaded_request".to_string()],
        }
    }

    fn fixture_provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://fixture".to_string(),
            provider_kind: "local_folder".to_string(),
            action: "list_models".to_string(),
            execution_backend: "rust_model_mount_fixture_inventory".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            item_refs: vec!["model://fixture/qwen3".to_string()],
            evidence_refs: vec!["daemon_fixture_list_models_request".to_string()],
        }
    }

    fn hosted_provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://openai".to_string(),
            provider_kind: "openai".to_string(),
            action: "list_models".to_string(),
            execution_backend: "rust_model_mount_hosted_provider_inventory".to_string(),
            api_format: Some("openai".to_string()),
            driver: Some("openai_compatible".to_string()),
            backend_ref: None,
            provider_status: Some("configured".to_string()),
            item_refs: vec![],
            evidence_refs: vec!["operator_provider_config".to_string()],
        }
    }

    #[test]
    fn provider_inventory_child_module_owns_planner_surface() {
        let result = plan_provider_inventory(&provider_inventory_request())
            .expect("native-local provider inventory planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(result.action, "list_loaded");
        assert_eq!(
            result.operation_kind,
            "model_mount.provider.inventory.list_loaded"
        );
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_inventory"
        );
        assert_eq!(result.item_count, 1);
        assert_eq!(
            result.item_refs,
            vec!["model_instance://native/qwen3".to_string()]
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_inventory".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_provider_inventory_truth_required".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result.inventory_hash.starts_with("sha256:"));
        assert_eq!(result.rust_core_boundary, "model_mount.provider_inventory");
        assert_eq!(result.record_dir, "model-provider-inventory");
        assert!(result.record_id.starts_with("provider_inventory_provider_"));
        assert_eq!(result.record["id"], result.record_id);
        assert_eq!(
            result.record["object"],
            "ioi.model_mount_provider_inventory"
        );
        assert_eq!(
            result.record["rust_core_boundary"],
            "model_mount.provider_inventory"
        );
        assert_eq!(result.record["inventory_hash"], result.inventory_hash);
    }

    #[test]
    fn native_local_provider_inventory_is_planned_in_rust_model_mount() {
        let result = plan_provider_inventory(&provider_inventory_request())
            .expect("native-local provider inventory planned in Rust");

        assert_eq!(result.action, "list_loaded");
        assert_eq!(result.status, "listed");
        assert_eq!(result.item_count, 1);
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_inventory_backend".to_string()));
    }

    #[test]
    fn fixture_provider_inventory_is_planned_in_rust_model_mount() {
        let mut request = fixture_provider_inventory_request();

        let result = plan_provider_inventory(&request)
            .expect("fixture provider model inventory planned in Rust");

        assert_eq!(result.action, "list_models");
        assert_eq!(
            result.operation_kind,
            "model_mount.provider.inventory.list_models"
        );
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert_eq!(result.driver, "fixture");
        assert_eq!(result.item_count, 1);
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_registry_fixture".to_string()));

        request.action = "list_loaded".to_string();
        request.item_refs = vec!["model_instance://fixture/qwen3".to_string()];
        let result = plan_provider_inventory(&request)
            .expect("fixture provider loaded inventory planned in Rust");
        assert_eq!(result.action, "list_loaded");
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_instance_registry_fixture".to_string()));
    }

    #[test]
    fn hosted_provider_inventory_is_planned_in_rust_without_js_transport() {
        let mut request = hosted_provider_inventory_request();

        let result = plan_provider_inventory(&request)
            .expect("hosted provider metadata inventory planned in Rust");

        assert_eq!(result.action, "list_models");
        assert_eq!(
            result.operation_kind,
            "model_mount.provider.inventory.list_models"
        );
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "hosted_provider_metadata");
        assert_eq!(result.backend_id, "backend.hosted.openai");
        assert_eq!(result.driver, "hosted_provider_metadata");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_hosted_provider_inventory"
        );
        assert_eq!(result.item_refs, Vec::<String>::new());
        assert_eq!(result.item_count, 0);
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_hosted_provider_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"hosted_provider_transport_not_executed".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"wallet_network_provider_secret_boundary".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"hosted_provider_catalog_metadata_recorded".to_string()));
        assert!(result.record_id.starts_with("provider_inventory_provider_"));
        assert_eq!(result.record["id"], result.record_id);
        assert_eq!(
            result.record["rust_core_boundary"],
            "model_mount.provider_inventory"
        );

        request.action = "list_loaded".to_string();
        let result = plan_provider_inventory(&request)
            .expect("hosted provider loaded metadata inventory planned in Rust");
        assert_eq!(result.action, "list_loaded");
        assert!(result
            .evidence_refs
            .contains(&"hosted_provider_loaded_instance_replay_required".to_string()));
    }

    #[test]
    fn native_local_provider_inventory_rejects_unsupported_backend_and_action() {
        let mut request = provider_inventory_request();
        request.execution_backend = "daemon_js".to_string();

        let error = plan_provider_inventory(&request)
            .expect_err("inventory planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderInventoryBackend);

        request = provider_inventory_request();
        request.action = "scan".to_string();
        let error = plan_provider_inventory(&request)
            .expect_err("inventory planner only supports explicit listing actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderInventoryAction);
    }
}
