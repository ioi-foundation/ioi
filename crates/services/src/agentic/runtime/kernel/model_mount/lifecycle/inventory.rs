use serde::{Deserialize, Serialize};
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
    pub status: String,
    pub backend: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub item_refs: Vec<String>,
    pub item_count: usize,
    pub evidence_refs: Vec<String>,
    pub inventory_hash: String,
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
        status: "listed".to_string(),
        backend: provider_inventory_backend(request),
        backend_id: provider_inventory_backend_id(request),
        driver: provider_inventory_driver(request),
        execution_backend: request.execution_backend.clone(),
        item_refs: request.item_refs.clone(),
        item_count: request.item_refs.len(),
        evidence_refs: provider_inventory_evidence_refs(request),
        inventory_hash: String::new(),
    };
    result.inventory_hash = provider_inventory_hash(&result)?;
    Ok(result)
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

fn provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        "autopilot.native_local.fixture".to_string()
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
    } else {
        "fixture".to_string()
    }
}

fn provider_inventory_evidence_refs(request: &ModelMountProviderInventoryRequest) -> Vec<String> {
    let mut refs = vec!["rust_model_mount_provider_inventory".to_string()];
    if is_native_local_provider_inventory_backend(request) {
        refs.push("rust_model_mount_native_local_inventory_backend".to_string());
        refs.push("autopilot_native_local_backend_registry".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("autopilot_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
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
    let mut canonical = result.clone();
    canonical.inventory_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
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

    #[test]
    fn provider_inventory_child_module_owns_planner_surface() {
        let result = plan_provider_inventory(&provider_inventory_request())
            .expect("native-local provider inventory planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(result.action, "list_loaded");
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
            .contains(&"rust_model_mount_native_local_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result.inventory_hash.starts_with("sha256:"));
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
