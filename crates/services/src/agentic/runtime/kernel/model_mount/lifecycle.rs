use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    push_unique_ref, require_non_empty, ModelMountError,
    MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
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
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInstanceLifecycleRequest {
    pub schema_version: String,
    pub instance_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub provider_ref: String,
    pub action: String,
    pub target_status: String,
    pub execution_backend: String,
    pub backend_ref: String,
    pub driver: String,
    pub provider_lifecycle_hash: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInstanceLifecycleResult {
    pub schema_version: String,
    pub instance_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub provider_ref: String,
    pub action: String,
    pub status: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub provider_lifecycle_hash: String,
    pub evidence_refs: Vec<String>,
    pub instance_lifecycle_hash: String,
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
        {
            return Err(ModelMountError::UnsupportedProviderLifecycleBackend);
        }
        Ok(())
    }
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

impl ModelMountInstanceLifecycleRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("instance_ref", &self.instance_ref)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("target_status", &self.target_status)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        require_non_empty("backend_ref", &self.backend_ref)?;
        require_non_empty("driver", &self.driver)?;
        require_non_empty("provider_lifecycle_hash", &self.provider_lifecycle_hash)?;
        if self.execution_backend.trim() != "rust_model_mount_instance_lifecycle" {
            return Err(ModelMountError::UnsupportedInstanceLifecycleBackend);
        }
        match self.action.trim() {
            "load" if self.target_status.trim() == "loaded" => Ok(()),
            "unload" if self.target_status.trim() == "unloaded" => Ok(()),
            "evict" if self.target_status.trim() == "evicted" => Ok(()),
            "supersede" if self.target_status.trim() == "superseded" => Ok(()),
            "load" | "unload" | "evict" | "supersede" => {
                Err(ModelMountError::InstanceLifecycleStatusMismatch)
            }
            _ => Err(ModelMountError::UnsupportedInstanceLifecycleAction),
        }
    }
}

pub(super) fn plan_provider_lifecycle(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
    request.validate()?;
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
    };
    result.lifecycle_hash = provider_lifecycle_hash(&result)?;
    Ok(result)
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

pub(super) fn plan_instance_lifecycle(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<ModelMountInstanceLifecycleResult, ModelMountError> {
    request.validate()?;
    let mut result = ModelMountInstanceLifecycleResult {
        schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
        instance_ref: request.instance_ref.clone(),
        endpoint_ref: request.endpoint_ref.clone(),
        model_ref: request.model_ref.clone(),
        provider_ref: request.provider_ref.clone(),
        action: request.action.clone(),
        status: request.target_status.clone(),
        backend_id: request.backend_ref.clone(),
        driver: request.driver.clone(),
        execution_backend: request.execution_backend.clone(),
        provider_lifecycle_hash: request.provider_lifecycle_hash.clone(),
        evidence_refs: instance_lifecycle_evidence_refs(request),
        instance_lifecycle_hash: String::new(),
    };
    result.instance_lifecycle_hash = instance_lifecycle_hash(&result)?;
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
    } else {
        "fixture".to_string()
    }
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

fn provider_lifecycle_evidence_refs(request: &ModelMountProviderLifecycleRequest) -> Vec<String> {
    let mut refs = vec!["rust_model_mount_provider_lifecycle".to_string()];
    if is_native_local_provider_lifecycle_backend(request) {
        refs.push("rust_model_mount_native_local_lifecycle_backend".to_string());
        if matches!(request.action.trim(), "health" | "load") {
            refs.push("autopilot_native_local_backend_registry".to_string());
        }
        if matches!(request.action.trim(), "load" | "unload") {
            refs.push("autopilot_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
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

fn instance_lifecycle_evidence_refs(request: &ModelMountInstanceLifecycleRequest) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_instance_lifecycle".to_string(),
        "rust_model_mount_provider_lifecycle_bound".to_string(),
        "agentgres_model_instance_registry_planned".to_string(),
    ];
    for evidence_ref in &request.evidence_refs {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn provider_lifecycle_hash(
    result: &ModelMountProviderLifecycleResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.lifecycle_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
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

fn instance_lifecycle_hash(
    result: &ModelMountInstanceLifecycleResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.instance_lifecycle_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}
