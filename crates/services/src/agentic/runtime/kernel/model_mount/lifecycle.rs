mod instance;
mod inventory;
mod provider;

use serde::Deserialize;
use serde_json::{json, Value};

pub use instance::{ModelMountInstanceLifecycleRequest, ModelMountInstanceLifecycleResult};
pub use inventory::{ModelMountProviderInventoryRequest, ModelMountProviderInventoryResult};
pub use provider::{ModelMountProviderLifecycleRequest, ModelMountProviderLifecycleResult};

use super::ModelMountError;

#[derive(Debug, Deserialize)]
pub struct ModelMountProviderLifecycleBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderLifecycleRequest,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountProviderInventoryBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderInventoryRequest,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountInstanceLifecycleBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountInstanceLifecycleRequest,
}

pub(super) fn plan_provider_lifecycle(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
    provider::plan_provider_lifecycle(request)
}

pub(super) fn plan_provider_inventory(
    request: &ModelMountProviderInventoryRequest,
) -> Result<ModelMountProviderInventoryResult, ModelMountError> {
    inventory::plan_provider_inventory(request)
}

pub(super) fn plan_instance_lifecycle(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<ModelMountInstanceLifecycleResult, ModelMountError> {
    instance::plan_instance_lifecycle(request)
}

pub fn plan_model_mount_provider_lifecycle_response(
    request: ModelMountProviderLifecycleBridgeRequest,
) -> Result<Value, ModelMountError> {
    let result = plan_provider_lifecycle(&request.request)?;
    let status = result.status.clone();
    let backend = result.backend.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let lifecycle_hash = result.lifecycle_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_lifecycle_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backend_id": backend_id,
        "provider_backend": backend,
        "driver": driver,
        "execution_backend": execution_backend,
        "lifecycle_hash": lifecycle_hash,
        "evidence_refs": evidence_refs,
    }))
}

pub fn plan_model_mount_provider_inventory_response(
    request: ModelMountProviderInventoryBridgeRequest,
) -> Result<Value, ModelMountError> {
    let result = plan_provider_inventory(&request.request)?;
    let status = result.status.clone();
    let backend = result.backend.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let item_refs = result.item_refs.clone();
    let item_count = result.item_count;
    let inventory_hash = result.inventory_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_inventory_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backend_id": backend_id,
        "provider_backend": backend,
        "driver": driver,
        "execution_backend": execution_backend,
        "item_refs": item_refs,
        "item_count": item_count,
        "inventory_hash": inventory_hash,
        "evidence_refs": evidence_refs,
    }))
}

pub fn plan_model_mount_instance_lifecycle_response(
    request: ModelMountInstanceLifecycleBridgeRequest,
) -> Result<Value, ModelMountError> {
    let result = plan_instance_lifecycle(&request.request)?;
    let status = result.status.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let provider_lifecycle_hash = result.provider_lifecycle_hash.clone();
    let instance_lifecycle_hash = result.instance_lifecycle_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_instance_lifecycle_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backendId": backend_id.clone(),
        "backend_id": backend_id,
        "driver": driver,
        "execution_backend": execution_backend,
        "provider_lifecycle_hash": provider_lifecycle_hash,
        "instance_lifecycle_hash": instance_lifecycle_hash,
        "evidence_refs": evidence_refs,
    }))
}
