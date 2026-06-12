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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::command_protocol::DAEMON_CORE_COMMAND_SCHEMA_VERSION;
    use crate::agentic::runtime::kernel::model_mount::{
        MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
        MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
        MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
    };

    #[test]
    fn rust_core_shapes_model_mount_provider_lifecycle_command_response() {
        let request: ModelMountProviderLifecycleBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_provider_lifecycle",
            "backend": "rust_model_mount_native_local_lifecycle",
            "request": {
                "schema_version": MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "action": "load",
                "execution_backend": "rust_model_mount_native_local_lifecycle",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "evidence_refs": ["daemon_model_load_request"],
                "process_evidence_refs": ["autopilot_native_local_process_started"]
            }
        }))
        .expect("native-local lifecycle command request");

        let response =
            plan_model_mount_provider_lifecycle_response(request).expect("lifecycle planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_lifecycle_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_native_local_lifecycle"
        );
        assert_eq!(response["status"], "loaded");
        assert_eq!(
            response["backend_id"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response["provider_backend"],
            "autopilot.native_local.fixture"
        );
        assert_eq!(response["driver"], "native_local");
        assert!(response.get("backendId").is_none());
        assert!(response.get("providerBackend").is_none());
        assert!(response["lifecycle_hash"]
            .as_str()
            .expect("lifecycle hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_lifecycle_backend"));
    }

    #[test]
    fn rust_core_shapes_model_mount_provider_inventory_command_response() {
        let request: ModelMountProviderInventoryBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_provider_inventory",
            "backend": "rust_model_mount_native_local_inventory",
            "request": {
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "action": "list_loaded",
                "execution_backend": "rust_model_mount_native_local_inventory",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "item_refs": ["model_instance://native/qwen3"],
                "evidence_refs": ["daemon_native_local_list_loaded_request"]
            }
        }))
        .expect("native-local inventory command request");

        let response =
            plan_model_mount_provider_inventory_response(request).expect("inventory planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_inventory_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_native_local_inventory"
        );
        assert_eq!(response["status"], "listed");
        assert_eq!(
            response["backend_id"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response["provider_backend"],
            "autopilot.native_local.fixture"
        );
        assert_eq!(response["driver"], "native_local");
        assert_eq!(response["item_count"], 1);
        assert!(response.get("backendId").is_none());
        assert!(response.get("providerBackend").is_none());
        assert!(response.get("itemRefs").is_none());
        assert!(response.get("itemCount").is_none());
        assert!(response["inventory_hash"]
            .as_str()
            .expect("inventory hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_inventory_backend"));
    }

    #[test]
    fn rust_core_shapes_model_mount_instance_lifecycle_command_response() {
        let request: ModelMountInstanceLifecycleBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_instance_lifecycle",
            "backend": "rust_model_mount_instance_lifecycle",
            "request": {
                "schema_version": MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
                "instance_ref": "model_instance://native/qwen3",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "provider_ref": "provider.autopilot.local",
                "action": "load",
                "target_status": "loaded",
                "execution_backend": "rust_model_mount_instance_lifecycle",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "driver": "native_local",
                "provider_lifecycle_hash": "sha256:provider-lifecycle",
                "evidence_refs": ["rust_model_mount_provider_lifecycle"]
            }
        }))
        .expect("instance lifecycle command request");

        let response =
            plan_model_mount_instance_lifecycle_response(request).expect("instance planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_instance_lifecycle_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_instance_lifecycle");
        assert_eq!(response["status"], "loaded");
        assert_eq!(
            response["backendId"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(response["driver"], "native_local");
        assert_eq!(
            response["provider_lifecycle_hash"],
            "sha256:provider-lifecycle"
        );
        assert!(response.get("providerLifecycleHash").is_none());
        assert!(response["instance_lifecycle_hash"]
            .as_str()
            .expect("instance lifecycle hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_instance_lifecycle"));
    }
}
